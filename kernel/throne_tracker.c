#include <linux/err.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/stat.h>
#include <linux/namei.h>

#include "allowlist.h"
#include "klog.h" // IWYU pragma: keep
#include "ksu.h"
#include "ksud.h"
#include "manager.h"
#include "throne_tracker.h"
#include "kernel_compat.h"
#include "dynamic_manager.h"

#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/delay.h>

uid_t ksu_manager_uid = KSU_INVALID_UID;

static struct task_struct *throne_thread;

#define USER_DATA_BASE_PATH "/data/user_de"
#define PRIMARY_USER_PATH "/data/user_de/0"
#define MAX_SUPPORTED_USERS 32 // Supports up to 32 users
#define DATA_PATH_LEN 384 // 384 is enough for /data/app/<package>/base.apk and /data/user_de/{userid}/<package>
#define SMALL_BUFFER_SIZE 64
#define SCHEDULE_INTERVAL 100

// Global work buffer to avoid stack allocation
struct work_buffers {
	char path_buffer[DATA_PATH_LEN];
	char package_buffer[KSU_MAX_PACKAGE_NAME];
	char small_buffer[SMALL_BUFFER_SIZE];
	uid_t user_ids_buffer[MAX_SUPPORTED_USERS];
};

struct uid_data {
	struct list_head list;
	u32 uid;
	char package[KSU_MAX_PACKAGE_NAME];
	uid_t user_id;
};

struct deferred_path_info {
	struct list_head list;
	char path[DATA_PATH_LEN];
	char package_name[KSU_MAX_PACKAGE_NAME];
	uid_t user_id;
};

struct user_scan_ctx {
	struct list_head *deferred_paths;
	uid_t user_id;
	size_t pkg_count;
	size_t error_count;
	struct work_buffers *work_buf; // Passing the work buffer
	size_t processed_count;
};

struct user_dir_ctx {
	struct dir_context ctx;
	struct user_scan_ctx *scan_ctx;
};

struct user_id_ctx {
	struct dir_context ctx;
	uid_t *user_ids;
	size_t count;
	size_t max_count;
	size_t processed_count;
};

struct data_path {
	char dirpath[DATA_PATH_LEN];
	int depth;
	struct list_head list;
};

struct apk_path_hash {
	unsigned int hash;
	bool exists;
	struct list_head list;
};

static struct list_head apk_path_hash_list;

struct my_dir_context {
	struct dir_context ctx;
	struct list_head *data_path_list;
	char *parent_dir;
	void *private_data;
	int depth;
	int *stop;
	bool found_dynamic_manager;
	struct work_buffers *work_buf; // Passing the work buffer
	size_t processed_count;
};
// https://docs.kernel.org/filesystems/porting.html
// filldir_t (readdir callbacks) calling conventions have changed. Instead of returning 0 or -E... it returns bool now. false means "no more" (as -E... used to) and true - "keep going" (as 0 in old calling conventions). Rationale: callers never looked at specific -E... values anyway. -> iterate_shared() instances require no changes at all, all filldir_t ones in the tree converted.
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#define FILLDIR_RETURN_TYPE bool
#define FILLDIR_ACTOR_CONTINUE true
#define FILLDIR_ACTOR_STOP false
#else
#define FILLDIR_RETURN_TYPE int
#define FILLDIR_ACTOR_CONTINUE 0
#define FILLDIR_ACTOR_STOP -EINVAL
#endif

static struct work_buffers *get_work_buffer(void)
{
	static struct work_buffers global_buffer;
	return &global_buffer;
}

static int get_pkg_from_apk_path(char *pkg, const char *path)
{
	int len = strlen(path);
	if (len >= KSU_MAX_PACKAGE_NAME || len < 1)
		return -1;

	const char *last_slash = NULL;
	const char *second_last_slash = NULL;

	int i;
	for (i = len - 1; i >= 0; i--) {
		if (path[i] == '/') {
			if (!last_slash) {
				last_slash = &path[i];
			} else {
				second_last_slash = &path[i];
				break;
			}
		}
	}

	if (!last_slash || !second_last_slash)
		return -1;

	const char *last_hyphen = strchr(second_last_slash, '-');
	if (!last_hyphen || last_hyphen > last_slash)
		return -1;

	int pkg_len = last_hyphen - second_last_slash - 1;
	if (pkg_len >= KSU_MAX_PACKAGE_NAME || pkg_len <= 0)
		return -1;

	// Copying the package name
	strncpy(pkg, second_last_slash + 1, pkg_len);
	pkg[pkg_len] = '\0';

	return 0;
}

static void crown_manager(const char *apk, struct list_head *uid_data,
			  int signature_index, struct work_buffers *work_buf)
{
	if (get_pkg_from_apk_path(work_buf->package_buffer, apk) < 0) {
		pr_err("Failed to get package name from apk path: %s\n", apk);
		return;
	}

	pr_info("manager pkg: %s, signature_index: %d\n", work_buf->package_buffer, signature_index);

#ifdef KSU_MANAGER_PACKAGE
	// pkg is `/<real package>`
	if (strncmp(work_buf->package_buffer, KSU_MANAGER_PACKAGE, sizeof(KSU_MANAGER_PACKAGE))) {
		pr_info("manager package is inconsistent with kernel build: %s\n",
			KSU_MANAGER_PACKAGE);
		return;
	}
#endif

	struct uid_data *np;
	list_for_each_entry(np, uid_data, list) {
		if (strncmp(np->package, work_buf->package_buffer, KSU_MAX_PACKAGE_NAME) == 0) {
			pr_info("Crowning manager: %s(uid=%d, signature_index=%d, user=%u)\n",
				work_buf->package_buffer, np->uid, signature_index, np->user_id);

			if (signature_index == DYNAMIC_SIGN_INDEX || signature_index >= 2) {
				ksu_add_manager(np->uid, signature_index);
				if (!ksu_is_manager_uid_valid()) {
					ksu_set_manager_uid(np->uid);
				}
			} else {
				ksu_set_manager_uid(np->uid);
			}
			break;
		}
	}
}

FILLDIR_RETURN_TYPE scan_user_packages(struct dir_context *ctx, const char *name,
					       int namelen, loff_t off, u64 ino, unsigned int d_type)
{
	struct user_dir_ctx *uctx = container_of(ctx, struct user_dir_ctx, ctx);
	struct user_scan_ctx *scan_ctx = uctx->scan_ctx;

	if (!scan_ctx || !scan_ctx->deferred_paths)
		return FILLDIR_ACTOR_STOP;

	scan_ctx->processed_count++;
	if (scan_ctx->processed_count % SCHEDULE_INTERVAL == 0) {
		cond_resched();
	}

	if (d_type != DT_DIR || namelen <= 0)
		return FILLDIR_ACTOR_CONTINUE;
	if (name[0] == '.' && (namelen == 1 || (namelen == 2 && name[1] == '.')))
		return FILLDIR_ACTOR_CONTINUE;

	if (namelen >= KSU_MAX_PACKAGE_NAME) {
		pr_warn("Package name too long: %.*s (user %u)\n", namelen, name, scan_ctx->user_id);
		scan_ctx->error_count++;
		return FILLDIR_ACTOR_CONTINUE;
	}

	struct deferred_path_info *path_info = kzalloc(sizeof(struct deferred_path_info), GFP_KERNEL);
	if (!path_info) {
		pr_err("Memory allocation failed for path info: %.*s\n", namelen, name);
		scan_ctx->error_count++;
		return FILLDIR_ACTOR_CONTINUE;
	}

	int path_len = snprintf(path_info->path, sizeof(path_info->path), 
				"%s/%u/%.*s", USER_DATA_BASE_PATH, scan_ctx->user_id, namelen, name);
	if (path_len >= sizeof(path_info->path)) {
		pr_err("Path too long for: %.*s (user %u)\n", namelen, name, scan_ctx->user_id);
		kfree(path_info);
		scan_ctx->error_count++;
		return FILLDIR_ACTOR_CONTINUE;
	}

	path_info->user_id = scan_ctx->user_id;
	size_t copy_len = min_t(size_t, namelen, KSU_MAX_PACKAGE_NAME - 1);
	strncpy(path_info->package_name, name, copy_len);
	path_info->package_name[copy_len] = '\0';

	list_add_tail(&path_info->list, scan_ctx->deferred_paths);
	scan_ctx->pkg_count++;

	return FILLDIR_ACTOR_CONTINUE;
}

static int process_deferred_paths(struct list_head *deferred_paths, struct list_head *uid_list)
{
	struct deferred_path_info *path_info, *n;
	int success_count = 0;

	list_for_each_entry_safe(path_info, n, deferred_paths, list) {
		struct path path;
		int err = kern_path(path_info->path, LOOKUP_FOLLOW, &path);
		if (err) {
			pr_debug("Path lookup failed: %s (%d)\n", path_info->path, err);
			list_del(&path_info->list);
			kfree(path_info);
			continue;
		}

		struct kstat stat;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0) || defined(KSU_HAS_NEW_VFS_GETATTR)
		err = vfs_getattr(&path, &stat, STATX_UID, AT_STATX_SYNC_AS_STAT);
#else
		err = vfs_getattr(&path, &stat);
#endif
		path_put(&path);

		if (err) {
			pr_debug("Failed to get attributes: %s (%d)\n", path_info->path, err);
			list_del(&path_info->list);
			kfree(path_info);
			continue;
		}

		uid_t uid = from_kuid(&init_user_ns, stat.uid);
		if (uid == (uid_t)-1) {
			pr_warn("Invalid UID for: %s\n", path_info->path);
			list_del(&path_info->list);
			kfree(path_info);
			continue;
		}

		struct uid_data *uid_entry = kzalloc(sizeof(struct uid_data), GFP_KERNEL);
		if (!uid_entry) {
			pr_err("Memory allocation failed for UID entry: %s\n", path_info->path);
			list_del(&path_info->list);
			kfree(path_info);
			continue;
		}

		uid_entry->uid = uid;
		uid_entry->user_id = path_info->user_id;
		strncpy(uid_entry->package, path_info->package_name, KSU_MAX_PACKAGE_NAME - 1);
		uid_entry->package[KSU_MAX_PACKAGE_NAME - 1] = '\0';

		list_add_tail(&uid_entry->list, uid_list);
		success_count++;

		pr_info("Package: %s, UID: %u, User: %u\n", uid_entry->package, uid, path_info->user_id);

		list_del(&path_info->list);
		kfree(path_info);
		
		if (success_count % 10 == 0) {
			cond_resched();
		}
	}

	return success_count;
}

// Scan the primary user
static int scan_primary_user_apps(struct list_head *uid_list, 
				   size_t *pkg_count, size_t *error_count,
				   struct work_buffers *work_buf)
{
	struct file *dir_file;
	struct list_head deferred_paths;
	int ret;
	
	*pkg_count = *error_count = 0;
	INIT_LIST_HEAD(&deferred_paths);

	pr_info("Scanning primary user (0) applications in %s\n", PRIMARY_USER_PATH);

	dir_file = ksu_filp_open_compat(PRIMARY_USER_PATH, O_RDONLY, 0);
	if (IS_ERR(dir_file)) {
		pr_err("Cannot open primary user path: %s (%ld)\n", PRIMARY_USER_PATH, PTR_ERR(dir_file));
		return PTR_ERR(dir_file);
	}

	struct user_scan_ctx scan_ctx = {
		.deferred_paths = &deferred_paths,
		.user_id = 0,
		.pkg_count = 0,
		.error_count = 0,
		.work_buf = work_buf,
		.processed_count = 0
	};

	struct user_dir_ctx uctx = {
		.ctx.actor = scan_user_packages,
		.scan_ctx = &scan_ctx
	};

	ret = iterate_dir(dir_file, &uctx.ctx);
	filp_close(dir_file, NULL);

	int processed = process_deferred_paths(&deferred_paths, uid_list);
	
	*pkg_count = processed;
	*error_count = scan_ctx.error_count;

	pr_info("Primary user scan completed: %zu packages found, %zu errors\n", 
		*pkg_count, *error_count);

	return ret;
}

FILLDIR_RETURN_TYPE collect_user_ids(struct dir_context *ctx, const char *name,
				     int namelen, loff_t off, u64 ino, unsigned int d_type)
{
	struct user_id_ctx *uctx = container_of(ctx, struct user_id_ctx, ctx);

	uctx->processed_count++;
	if (uctx->processed_count % SCHEDULE_INTERVAL == 0) {
		cond_resched();
	}

	if (d_type != DT_DIR || namelen <= 0)
		return FILLDIR_ACTOR_CONTINUE;
	if (name[0] == '.' && (namelen == 1 || (namelen == 2 && name[1] == '.')))
		return FILLDIR_ACTOR_CONTINUE;

	uid_t uid = 0;
	for (int i = 0; i < namelen; i++) {
		if (name[i] < '0' || name[i] > '9')
			return FILLDIR_ACTOR_CONTINUE; // Skip non-numeric entries
		uid = uid * 10 + (name[i] - '0');
	}

	if (uctx->count >= uctx->max_count)
		return FILLDIR_ACTOR_STOP;

	uctx->user_ids[uctx->count++] = uid;
	return FILLDIR_ACTOR_CONTINUE;
}

// Retrieve all active users (optional)
static int get_all_active_users(struct work_buffers *work_buf, size_t *found_count)
{
	struct file *dir_file;
	int ret;

	*found_count = 0;

	dir_file = ksu_filp_open_compat(USER_DATA_BASE_PATH, O_RDONLY, 0);
	if (IS_ERR(dir_file)) {
		pr_err("Cannot open user data base path: %s (%ld)\n", USER_DATA_BASE_PATH, PTR_ERR(dir_file));
		return PTR_ERR(dir_file);
	}

	struct user_id_ctx uctx = {
		.ctx.actor = collect_user_ids,
		.user_ids = work_buf->user_ids_buffer,
		.count = 0,
		.max_count = MAX_SUPPORTED_USERS,
		.processed_count = 0
	};

	ret = iterate_dir(dir_file, &uctx.ctx);
	filp_close(dir_file, NULL);

	*found_count = uctx.count;
	if (uctx.count > 0) {
		pr_info("Found %zu active users: ", uctx.count);
		for (size_t i = 0; i < uctx.count; i++) {
			pr_cont("%u ", work_buf->user_ids_buffer[i]);
		}
		pr_cont("\n");
	}

	return ret;
}

// Scan other users' applications (optional)
static int scan_secondary_users_apps(struct list_head *uid_list, 
				     struct work_buffers *work_buf, size_t user_count,
				     size_t *total_pkg_count, size_t *total_error_count)
{
	int ret = 0;
	*total_pkg_count = *total_error_count = 0;

	for (size_t i = 0; i < user_count; i++) {
		// Skip the main user since it was already scanned in the first step.
		if (work_buf->user_ids_buffer[i] == 0)
			continue;

		struct file *dir_file;
		struct list_head deferred_paths;
		INIT_LIST_HEAD(&deferred_paths);
		
		snprintf(work_buf->path_buffer, sizeof(work_buf->path_buffer), 
			"%s/%u", USER_DATA_BASE_PATH, work_buf->user_ids_buffer[i]);

		dir_file = ksu_filp_open_compat(work_buf->path_buffer, O_RDONLY, 0);
		if (IS_ERR(dir_file)) {
			pr_debug("Cannot open user path: %s (%ld)\n", work_buf->path_buffer, PTR_ERR(dir_file));
			(*total_error_count)++;
			continue;
		}

		struct user_scan_ctx scan_ctx = {
			.deferred_paths = &deferred_paths,
			.user_id = work_buf->user_ids_buffer[i],
			.pkg_count = 0,
			.error_count = 0,
			.work_buf = work_buf,
			.processed_count = 0
		};

		struct user_dir_ctx uctx = {
			.ctx.actor = scan_user_packages,
			.scan_ctx = &scan_ctx
		};

		ret = iterate_dir(dir_file, &uctx.ctx);
		filp_close(dir_file, NULL);

		int processed = process_deferred_paths(&deferred_paths, uid_list);
		
		*total_pkg_count += processed;
		*total_error_count += scan_ctx.error_count;

		if (processed > 0 || scan_ctx.error_count > 0)
			pr_info("User %u: %d packages, %zu errors\n",
				work_buf->user_ids_buffer[i], processed, scan_ctx.error_count);

		cond_resched();
	}

	return ret;
}

int scan_user_data_for_uids(struct list_head *uid_list, bool scan_all_users)
{
	if (!uid_list)
		return -EINVAL;

	struct work_buffers *work_buf = get_work_buffer();
	if (!work_buf) {
		pr_err("Failed to get work buffer\n");
		return -ENOMEM;
	}
	//  Scan the primary user (User 0)
	size_t primary_pkg_count, primary_error_count;
	int ret = scan_primary_user_apps(uid_list, &primary_pkg_count, &primary_error_count, work_buf);
	if (ret < 0 && primary_pkg_count == 0) {
		pr_err("Primary user scan failed completely: %d\n", ret);
		return ret;
	}

	// If you don't need to scan all users, stop here.
	if (!scan_all_users) {
		pr_info("Scan completed (primary user only): %zu packages, %zu errors\n",
			primary_pkg_count, primary_error_count);
		return primary_pkg_count > 0 ? 0 : -ENOENT;
	}

	// Retrieve all active users
	size_t active_users;
	ret = get_all_active_users(work_buf, &active_users);
	if (ret < 0 || active_users == 0) {
		pr_warn("Failed to get active users, using primary user only: %d\n", ret);
		return primary_pkg_count > 0 ? 0 : -ENOENT;
	}

	size_t secondary_pkg_count, secondary_error_count;
	ret = scan_secondary_users_apps(uid_list, work_buf, active_users,
					&secondary_pkg_count, &secondary_error_count);

	size_t total_packages = primary_pkg_count + secondary_pkg_count;
	size_t total_errors = primary_error_count + secondary_error_count;

	if (total_errors > 0)
		pr_warn("Scan completed with %zu errors\n", total_errors);

	pr_info("Complete scan finished: %zu users, %zu total packages\n", 
		active_users, total_packages);

	return total_packages > 0 ? 0 : -ENOENT;
}

FILLDIR_RETURN_TYPE my_actor(struct dir_context *ctx, const char *name,
			     int namelen, loff_t off, u64 ino,
			     unsigned int d_type)
{
	struct my_dir_context *my_ctx =
		container_of(ctx, struct my_dir_context, ctx);
	struct work_buffers *work_buf = my_ctx->work_buf;

	if (!my_ctx) {
		pr_err("Invalid context\n");
		return FILLDIR_ACTOR_STOP;
	}

	my_ctx->processed_count++;
	if (my_ctx->processed_count % SCHEDULE_INTERVAL == 0) {
		cond_resched();
	}

	if (my_ctx->stop && *my_ctx->stop) {
		pr_info("Stop searching\n");
		return FILLDIR_ACTOR_STOP;
	}

	if (!strncmp(name, "..", namelen) || !strncmp(name, ".", namelen))
		return FILLDIR_ACTOR_CONTINUE; // Skip "." and ".."

	if (d_type == DT_DIR && namelen >= 8 && !strncmp(name, "vmdl", 4) &&
	    !strncmp(name + namelen - 4, ".tmp", 4)) {
		pr_info("Skipping directory: %.*s\n", namelen, name);
		return FILLDIR_ACTOR_CONTINUE; // Skip staging package
	}

	if (snprintf(work_buf->path_buffer, DATA_PATH_LEN, "%s/%.*s", my_ctx->parent_dir, 
		     namelen, name) >= DATA_PATH_LEN) {
		pr_err("Path too long: %s/%.*s\n", my_ctx->parent_dir, namelen,
				name);
		return FILLDIR_ACTOR_CONTINUE;
	}

	if (d_type == DT_DIR && my_ctx->depth > 0 &&
		(my_ctx->stop && !*my_ctx->stop)) {
		struct data_path *data = kmalloc(sizeof(struct data_path), GFP_KERNEL);

		if (!data) {
			pr_err("Failed to allocate memory for %s\n", work_buf->path_buffer);
			return FILLDIR_ACTOR_CONTINUE;
		}

		strscpy(data->dirpath, work_buf->path_buffer, DATA_PATH_LEN);
		data->depth = my_ctx->depth - 1;
		list_add_tail(&data->list, my_ctx->data_path_list);
	} else {
		if ((namelen == 8) && (strncmp(name, "base.apk", namelen) == 0)) {
			struct apk_path_hash *pos, *n;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
			unsigned int hash = full_name_hash(work_buf->path_buffer, strlen(work_buf->path_buffer));
#else
			unsigned int hash = full_name_hash(NULL, work_buf->path_buffer, strlen(work_buf->path_buffer));
#endif
			list_for_each_entry(pos, &apk_path_hash_list, list) {
				if (hash == pos->hash) {
					pos->exists = true;
					return FILLDIR_ACTOR_CONTINUE;
				}
			}

			int signature_index = -1;
			bool is_multi_manager = is_dynamic_manager_apk(
				work_buf->path_buffer, &signature_index);

			pr_info("Found new base.apk at path: %s, is_multi_manager: %d, signature_index: %d\n",
				work_buf->path_buffer, is_multi_manager, signature_index);
				
			// Check for dynamic sign or multi-manager signatures
			if (is_multi_manager && (signature_index == DYNAMIC_SIGN_INDEX || signature_index >= 2)) {
				my_ctx->found_dynamic_manager = true;
				crown_manager(work_buf->path_buffer, my_ctx->private_data, 
								signature_index, work_buf);

				struct apk_path_hash *apk_data = kmalloc(sizeof(struct apk_path_hash), GFP_KERNEL);
				if (apk_data) {
					apk_data->hash = hash;
					apk_data->exists = true;
					list_add_tail(&apk_data->list, &apk_path_hash_list);
				}
			} else if (is_manager_apk(work_buf->path_buffer)) {
				crown_manager(work_buf->path_buffer,
						my_ctx->private_data, 0, work_buf);
				
				if (!my_ctx->found_dynamic_manager && !ksu_is_dynamic_manager_enabled()) {
					*my_ctx->stop = 1;
				}

				// Manager found, clear APK cache list
				if (!ksu_is_dynamic_manager_enabled()) {
					list_for_each_entry_safe(pos, n, &apk_path_hash_list, list) {
						list_del(&pos->list);
						kfree(pos);
					}
				}
			} else {
				struct apk_path_hash *apk_data = kmalloc(sizeof(struct apk_path_hash), GFP_KERNEL);
				if (apk_data) {
					apk_data->hash = hash;
					apk_data->exists = true;
					list_add_tail(&apk_data->list, &apk_path_hash_list);
				}
			}
		}
	}

	return FILLDIR_ACTOR_CONTINUE;
}

void search_manager(const char *path, int depth, struct list_head *uid_data)
{
	int i, stop = 0;
	struct list_head data_path_list;
	struct work_buffers *work_buf = get_work_buffer();
	
	if (!work_buf) {
		pr_err("Failed to get work buffer for search_manager\n");
		return;
	}
	
	INIT_LIST_HEAD(&data_path_list);
	INIT_LIST_HEAD(&apk_path_hash_list);
	unsigned long data_app_magic = 0;
	bool found_dynamic_manager = false;

	// Initialize APK cache list
	struct apk_path_hash *pos, *n;
	list_for_each_entry(pos, &apk_path_hash_list, list) {
		pos->exists = false;
	}

	// First depth
	struct data_path data;
	strscpy(data.dirpath, path, DATA_PATH_LEN);
	data.depth = depth;
	list_add_tail(&data.list, &data_path_list);

	for (i = depth; i >= 0; i--) {
		struct data_path *pos, *n;

		list_for_each_entry_safe(pos, n, &data_path_list, list) {
			struct my_dir_context ctx = { .ctx.actor = my_actor,
				.data_path_list = &data_path_list,
				.parent_dir = pos->dirpath,
				.private_data = uid_data,
				.depth = pos->depth,
				.stop = &stop,
				.found_dynamic_manager = false,
				.work_buf = work_buf,
				.processed_count = 0 };
			struct file *file;

			if (!stop) {
				file = ksu_filp_open_compat(pos->dirpath, O_RDONLY | O_NOFOLLOW | O_DIRECTORY, 0);
				if (IS_ERR(file)) {
					pr_err("Failed to open directory: %s, err: %ld\n", pos->dirpath, PTR_ERR(file));
					goto skip_iterate;
				}

				// grab magic on first folder, which is /data/app
				if (!data_app_magic) {
					if (file->f_inode->i_sb->s_magic) {
						data_app_magic = file->f_inode->i_sb->s_magic;
						pr_info("%s: dir: %s got magic! 0x%lx\n", __func__, pos->dirpath, data_app_magic);
					} else {
						filp_close(file, NULL);
						goto skip_iterate;
					}
				}

				if (file->f_inode->i_sb->s_magic != data_app_magic) {
					pr_info("%s: skip: %s magic: 0x%lx expected: 0x%lx\n", __func__, pos->dirpath, 
						file->f_inode->i_sb->s_magic, data_app_magic);
					filp_close(file, NULL);
					goto skip_iterate;
				}

				iterate_dir(file, &ctx.ctx);
				filp_close(file, NULL);
				
				if (ctx.found_dynamic_manager) {
					found_dynamic_manager = true;
				}

				cond_resched();
			}
skip_iterate:
			list_del(&pos->list);
			if (pos != &data)
				kfree(pos);
		}

		cond_resched();
	}

	// clear apk_path_hash_list unconditionally
	pr_info("search manager: cleanup!\n");
	list_for_each_entry_safe(pos, n, &apk_path_hash_list, list) {
		list_del(&pos->list);
		kfree(pos);
	}
}

static bool is_uid_exist(uid_t uid, char *package, void *data)
{
	struct list_head *list = (struct list_head *)data;
	struct uid_data *np;

	bool exist = false;
	list_for_each_entry(np, list, list) {
		if (np->uid == uid % 100000 &&
			strncmp(np->package, package, KSU_MAX_PACKAGE_NAME) == 0) {
			exist = true;
			break;
		}
	}
	return exist;
}

static void track_throne_function(void)
{
	struct list_head uid_list;
	INIT_LIST_HEAD(&uid_list);
	// scan user data for uids
	int ret = scan_user_data_for_uids(&uid_list, scan_all_users);
	
	if (ret < 0) {
		pr_err("Improved UserDE UID scan failed: %d. scan_all_users=%d\n", ret, scan_all_users);
		goto out;
	}

	// now update uid list
	struct uid_data *np;
	struct uid_data *n;

	// first, check if manager_uid exist!
	bool manager_exist = false;
	bool dynamic_manager_exist = false;

	list_for_each_entry(np, &uid_list, list) {
		// if manager is installed in work profile, the uid in packages.list is still equals main profile
		// don't delete it in this case!
		int manager_uid = ksu_get_manager_uid() % 100000;
		if (np->uid == manager_uid) {
			manager_exist = true;
			break;
		}
	}

	// Check for dynamic managers
	if (ksu_is_dynamic_manager_enabled()) {
		dynamic_manager_exist = ksu_has_dynamic_managers();
		
		if (!dynamic_manager_exist) {
			list_for_each_entry(np, &uid_list, list) {
			// Check if this uid is a dynamic manager (not the traditional manager)
				if (ksu_is_any_manager(np->uid) && np->uid != ksu_get_manager_uid()) {
					dynamic_manager_exist = true;
					break;
				}
			}
		}
	}

	if (!manager_exist) {
		if (ksu_is_manager_uid_valid()) {
			pr_info("manager is uninstalled, invalidate it!\n");
			ksu_invalidate_manager_uid();
			goto prune;
		}
		pr_info("Searching manager...\n");
		search_manager("/data/app", 2, &uid_list);
		pr_info("Search manager finished\n");
		// Always perform search when called from dynamic manager rescan
	} else if (!dynamic_manager_exist && ksu_is_dynamic_manager_enabled()) {
		pr_info("Dynamic sign enabled, Searching manager...\n");
		search_manager("/data/app", 2, &uid_list);
		pr_info("Search Dynamic sign manager finished\n");
	}

prune:
	// then prune the allowlist
	ksu_prune_allowlist(is_uid_exist, &uid_list);
out:
	// free uid_list
	list_for_each_entry_safe(np, n, &uid_list, list) {
		list_del(&np->list);
		kfree(np);
	}
}

static int throne_tracker_thread(void *data)
{
	pr_info("%s: pid: %d started\n", __func__, current->pid);
	// for the kthread, we need to escape to root
	// since it does not inherit the caller's context.
	// this runs as root but without the capabilities, so call it with false
	escape_to_root(false);
	track_throne_function();
	throne_thread = NULL;
	smp_mb();
	pr_info("%s: pid: %d exit!\n", __func__, current->pid);
	return 0;
}

void track_throne(void)
{
	static bool throne_tracker_first_run __read_mostly = true;
	if (unlikely(throne_tracker_first_run)) {
		track_throne_function();
		throne_tracker_first_run = false;
		return;
	}

	smp_mb();
	if (throne_thread != NULL) // single instance lock
		return;

	throne_thread = kthread_run(throne_tracker_thread, NULL, "throne_tracker");
	if (IS_ERR(throne_thread)) {
		throne_thread = NULL;
		return;
	}
}

void ksu_throne_tracker_init(void)
{
	// nothing to do
}

void ksu_throne_tracker_exit(void)
{
	// nothing to do
}
