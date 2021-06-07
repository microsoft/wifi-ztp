/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _TOOLS_LINUX_COMPILER_H_
#define _TOOLS_LINUX_COMPILER_H_

/* Are two types/vars the same type (ignoring qualifiers)? */
#ifndef __same_type
# define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#endif

#define __unused(x) (void)(x)

#endif /* _TOOLS_LINUX_COMPILER_H */
