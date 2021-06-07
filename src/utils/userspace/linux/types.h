/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _TOOLS_LINUX_TYPES_H_
#define _TOOLS_LINUX_TYPES_H_

struct list_head {
	struct list_head *next, *prev;
};

struct hlist_head {
	struct hlist_node *first;
};

struct hlist_node {
	struct hlist_node *next, **pprev;
};

#endif /* _TOOLS_LINUX_TYPES_H_ */
