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

/* seccomp_launch.c

   Usage: seccomp_launch [-f bpf-filter-blob]... prog arg...

   Detailed Explanation:
   This is a "launcher" wrapper. It reads raw BPF instructions (binary blob)
   from a file, installs them into the kernel via seccomp, and then execvp()s
   the user's desired program.
   
   Because seccomp filters persist across execvp(), the launched program
   will run under the restrictions of the loaded filter.
*/

#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); } while (0)

static int
seccomp(unsigned int operation, unsigned int flags, void *args)
{
    return syscall(__NR_seccomp, operation, flags, args);
}

/* Function to read filter from disk and install it */
static void
loadFilter(char *filterPathname)
{
    static bool noNewPrivsAlreadySet = false;
    struct sock_fprog fprog;
    struct sock_filter *filter;
    int filterSize;
    struct stat sb;
    int fd;

    /* We must set PR_SET_NO_NEW_PRIVS before installing a filter.
       This prevents the launched program from utilizing setuid bits 
       to elevate privileges, which could be dangerous if the user controls the filter.
    */
    if (!noNewPrivsAlreadySet) {        /* Only need to do this once */
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
            errExit("prctl");
        noNewPrivsAlreadySet = true;
    }

    /* Open the file containing the raw BPF instructions */
    fd = open(filterPathname, O_RDONLY);
    if (fd == -1)
        errExit("open");

    /* Get file size to allocate buffer */
    if (fstat(fd, &sb) == -1)
        errExit("fstat");

    filterSize = sb.st_size;
    
    /* Validation: BPF programs are arrays of 'struct sock_filter'. 
       The file size must be a multiple of the struct size. */
    if (filterSize % sizeof(struct sock_filter) != 0) {
        fprintf(stderr, "Filter has odd size\n");
        exit(EXIT_FAILURE);
    }

    filter = malloc(filterSize);
    if (filter == NULL)
        errExit("malloc");

    /* Read the BPF blob into memory */
    if (read(fd, filter, filterSize) != filterSize) {
        fprintf(stderr, "Failure reading filter\n");
        exit(EXIT_FAILURE);
    }

    if (close(fd) == -1)
        errExit("close");

    /* Setup the seccomp program structure */
    fprog.len = filterSize / sizeof(struct sock_filter);
    fprog.filter = filter;

    /* Install the filter into the kernel */
    if (seccomp(SECCOMP_SET_MODE_FILTER, 0, &fprog) == -1)
        errExit("seccomp");
}

static void
usageError(char *pname, char *msg)
{
    fprintf(stderr, "%s", msg);
    fprintf(stderr, "Usage: %s [-f filter] prog arg...\n", pname);
    exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
    int opt;

    /* Parse command-line arguments */
    while ((opt = getopt(argc, argv, "f:")) != -1) {
        switch (opt) {

        case 'f':               /* -f indicates a filter file to load */
            loadFilter(optarg);
            break;

        default:
            usageError(argv[0], "Bad option\n");
        }
    }

    /* Ensure a command was provided to run */
    if (optind >= argc || strcmp(argv[1], "--help") == 0)
        usageError(argv[0], "No program specified\n");

    /* Replace the current process image with the requested program.
       The seccomp filters installed by loadFilter() will remain active
       for the new program.
    */
    execvp(argv[optind], &argv[optind]);
    errExit("execve");
}


