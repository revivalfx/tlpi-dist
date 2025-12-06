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

/* libseccomp_demo.c

   Summary:
   This program uses the 'libseccomp' library to generate a seccomp-BPF
   filter. Using this library is generally preferred over manually
   constructing BPF instruction arrays (struct sock_filter) because it
   handles architecture specifics (syscall numbers differ between x86, ARM, etc.)
   and endianness automatically.

   The program creates a whitelist-style filter (default allow) that
   specifically denies the clone() and fork() system calls.
*/
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <seccomp.h>    /* Libseccomp API definitions */
#include "tlpi_hdr.h"   /* Presumed local header for error handling functions */

int main(int argc, char *argv[])
{
    int rc;
    scmp_filter_ctx ctx;

    /* Step 1: Initialize the Seccomp Context.
       
       seccomp_init() creates a new filter context.
       The argument SCMP_ACT_ALLOW establishes the "default action".
       
       SCMP_ACT_ALLOW means: "If a system call does not match any specific 
       rule we add later, allow it to execute." 
       
       If we wanted a strict whitelist (deny everything by default), we 
       would use SCMP_ACT_KILL or SCMP_ACT_ERRNO(...) here.
    */
    ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (ctx == NULL)
        fatal("seccomp_init() failed");

    /* Step 2: Add specific rules.
       
       We use seccomp_rule_add() to modify the filter.
       
       Rule A: Deny clone()
       - Context: ctx
       - Action: SCMP_ACT_ERRNO(EPERM). This means the syscall will not execute,
         and the caller will receive -1 with errno set to EPERM (Operation not permitted).
       - Syscall: SCMP_SYS(clone). This macro automatically looks up the 
         correct __NR_clone system call number for the current architecture.
       - Arg Count: 0. We are filtering based purely on the syscall number, 
         not checking the arguments (flags, stack, etc.) passed to clone().
    */
    rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(clone), 0);
    if (rc < 0)
        errExitEN(-rc, "seccomp_rule_add");

    /* Rule B: Deny fork()
       - Context: ctx
       - Action: SCMP_ACT_ERRNO(ENOTSUP). We use a different error code here 
         (Not Supported) just to demonstrate that we can control the precise 
         failure mode for different syscalls.
       - Syscall: SCMP_SYS(fork).
       - Arg Count: 0.
    */
    rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOTSUP), SCMP_SYS(fork), 0);
    if (rc < 0)
        errExitEN(-rc, "seccomp_rule_add");

    /* Step 3: Export the filter (Optional / Debugging).
       
       Before loading the filter into the kernel, we can export the logic 
       to file descriptors to inspect what libseccomp has generated.
       
       seccomp_export_pfc(ctx, 5):
       - PFC = Pseudo Filter Code. This is a human-readable representation 
         of the rules.
       - 5: This expects file descriptor 5 to be open (e.g., ./demo 5> output.pfc).
       
       seccomp_export_bpf(ctx, 6):
       - BPF = Berkeley Packet Filter. This is the raw binary code that the 
         Linux kernel actually executes.
       - 6: Expects file descriptor 6 to be open.
    */
    seccomp_export_pfc(ctx, 5);
    seccomp_export_bpf(ctx, 6);

    /* Step 4: Load the filter into the kernel.
       
       seccomp_load() compiles the context into BPF instructions and performs 
       the prctl(PR_SET_SECCOMP) or seccomp(SECCOMP_SET_MODE_FILTER) system call.
       
       Once this returns successfully, the filter is active. All future system 
       calls made by this process (and its children) are checked against the rules.
    */
    rc = seccomp_load(ctx);
    if (rc < 0)
        errExitEN(-rc, "seccomp_load");

    /* Step 5: Clean up.
       
       seccomp_release() frees the memory allocated for the user-space context.
       Note: This does NOT remove the filter from the kernel. Once a seccomp 
       filter is loaded, it is permanent for the life of the process.
    */
    seccomp_release(ctx);

    /* Step 6: Verify the filter works.
       
       We attempt to call fork(). Since we added a rule to deny fork() with 
       ENOTSUP, we expect this call to return -1 and errno to be ENOTSUP.
    */
    if (fork() != -1)
        fprintf(stderr, "fork() succeeded?!\n"); /* This should not be reached */
    else
        perror("fork"); /* Should print "fork: Operation not supported" */

    exit(EXIT_SUCCESS);
}


