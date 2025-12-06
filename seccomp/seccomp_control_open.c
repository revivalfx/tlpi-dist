/*************************************************************************\
*                  Copyright (C) Michael Kerrisk, 2019.                   *
*                                                                         *
* This program is free software. You may use, modify, and redistribute it *
* under the terms of the GNU General Public License as published by the   *
* Free Software Foundation, either version 3 or (at your option) any      *
* later version. This program is distributed without any warranty.  See   *
* the file COPYING.gpl-v3 for details.                                    *
\*************************************************************************/

/* Supplementary program for Chapter Z */

/* seccomp_control_open.c

   A simple seccomp filter example. Install a filter that triggers
   different failures in open(), depending on flags argument.
*/
/* seccomp_control_open.c

   Detailed Explanation:
   Demonstrates fine-grained control over a system call based on its arguments.
   
   Policy:
   - Allow open() if flags are O_RDONLY.
   - Kill process if O_CREAT is used.
   - Fail with error ENOTSUP if O_WRONLY or O_RDWR are used.
   
   Note: BPF can only perform checks on arguments that are simple values.
   It cannot dereference pointers (e.g., checking the filename string).
*/
#define _GNU_SOURCE
#include <stddef.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <sys/syscall.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include "tlpi_hdr.h"

/* For the x32 ABI, all system call numbers have bit 30 set */

#define X32_SYSCALL_BIT         0x40000000

/* The following is a hack to allow for systems (pre-Linux 4.14) that don't
   provide SECCOMP_RET_KILL_PROCESS, which kills (all threads in) a process.
   On those systems, define SECCOMP_RET_KILL_PROCESS as SECCOMP_RET_KILL
   (which simply kills the calling thread). */

#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS SECCOMP_RET_KILL
#endif

static int
seccomp(unsigned int operation, unsigned int flags, void *args)
{
    return syscall(__NR_seccomp, operation, flags, args);
}

static void
install_filter(void)
{
    struct sock_filter filter[] = {
        /* Load architecture */

        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                (offsetof(struct seccomp_data, arch))),

        /* Kill the process if the architecture is not what we expect */

        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, 2),

        /* Load system call number */

        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (offsetof(struct seccomp_data, nr))),

        /* Kill the process if this is an x32 system call (bit 30 is set) */

        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, X32_SYSCALL_BIT, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

        /* Allow syscalls other than open() and openat() */

        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_open, 2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 3, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

        /* Load second argument of open() (flags) into accumulator */

        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (offsetof(struct seccomp_data, args[1]))),

        /* Jump forward to flags processing */

        BPF_JUMP(BPF_JMP | BPF_JA, 1, 0, 0),

        /* Load third argument of openat() (flags) into accumulator */

        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (offsetof(struct seccomp_data, args[2]))),

        /* --- Flags Logic --- */
        
        /* 1. Check O_CREAT.
           BPF_JSET = Jump if Set (Bitwise AND).
           If (Accumulator & O_CREAT): Jump 0 (Kill).
           Else: Jump 1 (Next check). */
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, O_CREAT, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

        /* 2. Check Write Modes (O_WRONLY or O_RDWR).
           If (Accumulator & (O_WRONLY|O_RDWR)): Jump 0 (Error).
           Else: Jump 1 (Allow). */
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, O_WRONLY | O_RDWR, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOTSUP),

        /* 3. Allow (Implies Read Only and no Create) */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
    };

    struct sock_fprog prog = {
        .len = (unsigned short) (sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    if (seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog))
        errExit("seccomp");
    /* On Linux 3.16 and earlier (or if we have old glibc headers that
       don't define '__NR_seccomp', we must instead use:
            if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog))
                errExit("prctl-PR_SET_SECCOMP");
    */
}

int
main(int argc, char **argv)
{
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        errExit("prctl");

    install_filter();

    /* Test Cases */
    if (open("/tmp/a", O_RDONLY) == -1) // Should Succeed
        perror("open1");
    if (open("/tmp/a", O_WRONLY) == -1) // Should Fail (ENOTSUP)
        perror("open2");
    if (open("/tmp/a", O_RDWR) == -1)   // Should Fail (ENOTSUP)
        perror("open3");
    if (open("/tmp/a", O_CREAT | O_RDWR, 0600) == -1) // Should Kill Process
        perror("open4");

    exit(EXIT_SUCCESS);
}


