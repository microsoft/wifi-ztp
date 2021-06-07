/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_POISON_H
#define _LINUX_POISON_H

#include <stdint.h>

#define POISON_POINTER_DELTA 0

/*
 * These are non-NULL pointers that will result in page faults
 * under normal circumstances, used to verify that nobody uses
 * non-initialized list entries.
 */
#define LIST_POISON1  ((uint8_t *) 0x100 + POISON_POINTER_DELTA)
#define LIST_POISON2  ((uint8_t *) 0x122 + POISON_POINTER_DELTA)

#endif //_LINUX_POISON_H
