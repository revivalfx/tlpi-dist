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

/* dump_seccomp_filter.c

   Dump the contents of a process's BPF filter to a file, using the
   PTRACE_SECCOMP_GET_FILTER operation described in ptrace(2).

   Usage: dump_seccomp_filter PID dump-file [filter-index]

   A filter index of 0 (the default if no argument is supplied) corresponds
   to the most recently installed seccomp filter, with increasing values
   corresponding to previously installed filters. An ENOENT error return
   indicates that the index value exceeds the number of filters installed
   for the process.

   The dumped filter can be disassembled using a tool such as libseccomp's
   disassembler:

       libseccomp/tools/scmp_bpf_disasm < dump-file
*/
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>

#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); } while (0)

/* Fetch BPF filter with specified index for specified PID. A pointer to a
   dynamically allocated buffer is containing the filter code returned as the
   function result; the caller is responsible for freeing this buffer. If
   'instrCnt' is not NULL, then the number of instructions in the filter is
   placed in *instrCnt. */
/* fetchFilter:
   Helper function to interact with the target process via ptrace.
   
   Arguments:
   - pid: The Process ID to inspect.
   - filterIndex: Which filter in the stack to retrieve (0 = newest).
   - instrCnt: Output pointer to store the number of BPF instructions found.
   
   Returns:
   - A dynamically allocated pointer to the BPF program (array of sock_filter).
*/
static struct sock_filter *
fetchFilter(pid_t pid, int filterIndex, int *instrCnt)
{
    struct sock_filter *filterProg;
    int icnt;

    /* 1. Attach to the target process.
       PTRACE_ATTACH sends a SIGSTOP to the target, causing it to pause 
       execution so we can inspect it safely. 
    */
    if (ptrace(PTRACE_ATTACH, pid, 0, 0) == -1)
        errExit("ptrace - PTRACE_ATTACH");

    /* 2. Wait for the stop.
       We must wait for the target process to actually change state (stop)
       before we can issue ptrace queries.
    */
    if (waitpid(pid, NULL, 0) == -1)
        errExit("waitpid");

    /* 3. Discover the size of the filter.
       
       We invoke PTRACE_SECCOMP_GET_FILTER with the 'data' argument set to NULL.
       In this mode, the kernel returns the number of instructions (struct sock_filter)
       in the filter at 'filterIndex'.
    */
    icnt = ptrace(PTRACE_SECCOMP_GET_FILTER, pid, filterIndex, NULL);
    if (icnt == -1) {
        if (errno == ENOENT) {
            /* ENOENT means the index requested is higher than the number of 
               filters attached to the process. */
            fprintf(stderr, "No BPF program exists at index %d\n", filterIndex);
            exit(EXIT_FAILURE);
        } else if (errno == EACCES) {   
            /* EACCES usually means permissions issues. Inspecting seccomp filters
               requires CAP_SYS_ADMIN capabilities (root) unless you are the 
               direct parent. */
            fprintf(stderr, "You lack the CAP_SYS_ADMIN capability; "
                    "run this program as root\n");
            exit(EXIT_FAILURE);
        } else {
            errExit("ptrace - PTRACE_SECCOMP_GET_FILTER-1");
        }
    }

    /* 4. Allocate memory.
       We need a buffer large enough to hold 'icnt' number of sock_filter structures.
    */
    filterProg = calloc(icnt, sizeof(struct sock_filter));
    if (filterProg == NULL)
        errExit("calloc");

    /* 5. Fetch the actual filter data.
       We invoke PTRACE_SECCOMP_GET_FILTER again, this time passing our 
       allocated buffer. The kernel copies the BPF instructions into user space.
    */
    icnt = ptrace(PTRACE_SECCOMP_GET_FILTER, pid, filterIndex, filterProg);
    if (icnt == -1)
        errExit("ptrace - PTRACE_SECCOMP_GET_FILTER-2");

    if (instrCnt != NULL)
        *instrCnt = icnt;

    /* Note: We intentionally do not detach (PTRACE_DETACH) here because 
       the program exits immediately after this function returns, and the 
       OS cleans up ptrace attachments on exit. */

    return filterProg;
}

/* dumpFilter:
   Helper function to write the binary BPF data to a file.
*/
static void
dumpFilter(char *pathname, struct sock_filter *filterProg, int instrCnt)
{
    int fd;

    /* Open the output file, truncating it if it exists. 
       Permissions: Read/Write for user (0600). */
    fd = open(pathname, O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR);
    if (fd == -1)
        errExit("open");

    /* Write the array of struct sock_filter to the file */
    if (write(fd, filterProg, instrCnt * sizeof(struct sock_filter)) == -1)
        errExit("write");

    if (close(fd) == -1)
        errExit("close");

    fprintf(stderr, "Dumped %d BPF instructions\n", instrCnt);
}

int
main(int argc, char *argv[])
{
    struct sock_filter *filterProg;
    int filterIndex;
    int instrCnt;       /* Number of instructions in BPF filter */
    pid_t pid;

    /* Validate command line arguments */
    if (argc < 2 || strcmp(argv[1], "--help") == 0) {
        fprintf(stderr, "%s PID dump-file [filter-index]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    pid = atoi(argv[1]);
    
    /* If a 3rd argument is provided, use it as the index. Default to 0. */
    filterIndex = (argc > 3) ? atoi(argv[3]) : 0;

    /* Perform the fetch logic (ptrace attach, query, read) */
    filterProg = fetchFilter(pid, filterIndex, &instrCnt);

    /* Write result to disk */
    dumpFilter(argv[2], filterProg, instrCnt);

    /* Free the buffer (good practice, though we exit immediately) */
    free(filterProg);

    exit(EXIT_SUCCESS);
}


