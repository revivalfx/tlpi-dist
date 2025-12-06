/*************************************************************************\
* Copyright (C) Michael Kerrisk, 2019.                   *
* *
* This program is free software. You may use, modify, and redistribute it *
* under the terms of the GNU General Public License as published by the   *
* Free Software Foundation, either version 3 or (at your option) any      *
* later version. This program is distributed without any warranty.  See   *
* the file COPYING.gpl-v3 for details.                                    *
\*************************************************************************/

/* Supplementary program for Chapter Z */

/* seccomp_trap_sigsys.c

   Detailed Explanation:
   This program demonstrates the SECCOMP_RET_TRAP return action.
   Unlike SECCOMP_RET_KILL (which dies immediately) or SECCOMP_RET_ERRNO 
   (which fails quietly), RET_TRAP sends a SIGSYS signal to the process.
   
   This allows the program to catch the signal, inspect what happened 
   (though this specific example is simple), and potentially emulate the 
   syscall or simply log it, then continue execution.
*/

#define _GNU_SOURCE
#include <stddef.h>
#include <signal.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <sys/syscall.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include "tlpi_hdr.h" /* Presumed local header for common helpers */

/* For the x32 ABI, all system call numbers have bit 30 set */
#define X32_SYSCALL_BIT         0x40000000

/* Wrapper for seccomp syscall */
static int
seccomp(unsigned int operation, unsigned int flags, void *args)
{
    return syscall(__NR_seccomp, operation, flags, args);
}

static void
install_filter(void)
{
    struct sock_filter filter[] = {
        /* [0] Load architecture from seccomp_data */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                (offsetof(struct seccomp_data, arch))),

        /* [1] Check Architecture: Ensure x86-64.
           If Match: Jump 1 instruction (to [3]).
           If No Match: Jump 0 (continue to [2]). */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        
        /* [2] Kill if architecture is wrong */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),

        /* [3] Load system call number */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (offsetof(struct seccomp_data, nr))),

        /* [4] Check for x32 ABI (bit 30 set).
           If GE (Greater/Equal) than X32_SYSCALL_BIT: Jump 0 (continue to [5]).
           If Less: Jump 1 (skip to [6]). */
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, X32_SYSCALL_BIT, 0, 1),
        
        /* [5] Kill process if x32 syscall detected */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

        /* [6] Check specific syscall: getppid().
           If Equal: Jump 0 (continue to [7]).
           If Not Equal: Jump 1 (skip to [8]). */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getppid, 0, 1),
        
        /* [7] Action for getppid(): TRAP.
           This generates a SIGSYS signal. The syscall is NOT executed. */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
        
        /* [8] Action for all other syscalls: ALLOW. */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
    };

    struct sock_fprog prog = {
        .len = (unsigned short) (sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    if (seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog) == -1)
        errExit("seccomp");
    /* Note on legacy support for older kernels removed for brevity */
}

/* Signal Handler for SIGSYS.
   The kernel sends this signal when SECCOMP_RET_TRAP occurs.
*/
static void             
sigHandler(int sig)
{
    /* Note: printf is technically unsafe in a signal handler, 
       but used here for demonstration purposes. */
    printf("SIGSYS!\n");        
}

int
main(int argc, char **argv)
{
    struct sigaction sa;

    /* Prevent new privileges (required for seccomp without CAP_SYS_ADMIN) */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        errExit("prctl");

    install_filter();

    /* Register the signal handler for SIGSYS. 
       If we didn't do this, SIGSYS would terminate the process by default. 
    */
    sa.sa_flags = 0;
    sa.sa_handler = sigHandler;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSYS, &sa, NULL) == -1)
        errExit("sigaction");

    printf("About to call getppid()\n");

    /* Execute getppid(). 
       The filter sees this ID, triggers SECCOMP_RET_TRAP.
       The kernel suspends the syscall, sends SIGSYS to this thread.
       sigHandler() runs.
       sigHandler() returns.
       getppid() returns (likely with -1 and errno set, though void here).
    */
    (void) getppid();   

    /* Execution continues here after the signal handler returns */
    printf("Bye\n");

    exit(EXIT_SUCCESS);
}


