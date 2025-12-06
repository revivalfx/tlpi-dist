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

/* seccomp_logging.c

   A simple demonstration of the seccomp audit logging facility
   added in Linux 4.14.

   Run this program, and then examine the audit log using a command
   such as:

        # ausearch -ui $USER --format text --start recent -c seccomp_logging
*/

/* seccomp_logging.c

   Detailed Explanation:
   This program installs a filter that returns SECCOMP_RET_LOG for specific calls
   (in this stub, it returns LOG for *everything* that isn't killed).
   
   SECCOMP_RET_LOG executes the system call, but logs the attempt to the 
   system audit log. This is useful for "Dry Run" modes where you want to 
   see what a program is doing without breaking it.
*/

#define _GNU_SOURCE
#include <stddef.h>
#include <linux/audit.h>
#include <sys/syscall.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include "tlpi_hdr.h"

/* For the x32 ABI, all system call numbers have bit 30 set */

#define X32_SYSCALL_BIT         0x40000000

#ifndef SECCOMP_RET_LOG
#define SECCOMP_RET_LOG         0x7ffc0000U
#endif

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
        /* [0] Load Arch */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                (offsetof(struct seccomp_data, arch))),

        /* [1] Check x86-64 */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, 2),

        /* [2] Load Syscall Number */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (offsetof(struct seccomp_data, nr))),

        /* [3] Check x32 bit. Kill if set. */
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, X32_SYSCALL_BIT, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

        /* [5] Action: Log and Allow.
           Any syscall reaching here is executed, but an audit record is generated.
        */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_LOG),
    };

    struct sock_fprog prog = {
        .len = (unsigned short) (sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    if (seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog) == -1)
        errExit("seccomp");
}

int
main(int argc, char *argv[])
{
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        errExit("prctl");

    install_filter();

    geteuid();
    getppid();

    exit(EXIT_SUCCESS);
}
