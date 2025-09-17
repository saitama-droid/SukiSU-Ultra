#ifndef __KSU_H_UID_OBSERVER
#define __KSU_H_UID_OBSERVER

void ksu_throne_tracker_init();

void ksu_throne_tracker_exit();

void track_throne();

#include "ksu.h"

int ksu_update_uid_list(struct uid_list_data *uid_data);

#endif
