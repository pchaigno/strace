/*
 * Copyright (c) 2018 The strace developers.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#define HAVE_ARCH_UID16_SYSCALLS 1
#define SUPPORTED_PERSONALITIES 2
# define PERSONALITY0_AUDIT_ARCH { AUDIT_ARCH_RISCV64, 0 }
# define PERSONALITY1_AUDIT_ARCH { AUDIT_ARCH_RISCV32, 0 }
#define CAN_ARCH_BE_COMPAT_ON_64BIT_KERNEL 1
