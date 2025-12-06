/*************************************************************************\
* Copyright (C) Michael Kerrisk, 2019.                   *
* *
* This program is free software. You may use, modify, and redistribute it *
* under the terms of the GNU General Public License as published by the   *
* Free Software Foundation, either version 3 or (at your option) any      *
* later version. This program is distributed without any warranty.  See   *
* the file COPYING.gpl-v3 for details.                                    *
\*************************************************************************/

/* Supplementary program for Chapter 39 */

/* cap_launcher.c

   Launch a program with the credentials (UIDs, GIDs, supplementary GIDs)
   of a specified user, and with the capabilities specified on the
   command line.  The program relies on the use of ambient capabilities,
   a feature that first appeared in Linux 4.3.
*/

/* _GNU_SOURCE is defined to access Linux-specific extensions (like prctl) */
#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>      /* Required for prctl() system call */
#include <sys/capability.h>
#include <linux/securebits.h> /* For SECBIT_* constants */
#include <sys/types.h>
#include <pwd.h>            /* For getpwnam (user db lookup) */
#include <grp.h>            /* For getgrouplist (group db lookup) */
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include "cap_functions.h"  /* Helper function defined in previous file */
#include "tlpi_hdr.h"       /* Standard TLPI book header */

/* Helper function to display usage instructions */
static void
usage(char *pname)
{
    fprintf(stderr, "Usage: %s user cap,... cmd arg...\n", pname);
    fprintf(stderr, "\t'user' is the user with whose credentials\n");
    fprintf(stderr, "\t\tthe program is to be launched\n");
    fprintf(stderr, "\t'cap,...' is the set of capabilities with which\n");
    fprintf(stderr, "\t\tthe program is to be launched\n");
    fprintf(stderr, "\t'cmd' and 'arg...' specify the command plus\n");
    fprintf(stderr, "\t\tfor the program that is to be launched\n");
    exit(EXIT_FAILURE);
}

/* Switch credentials (user ID, group ID, supplementary groups) to
   those for the user named in 'user' */
static void
setCredentials(char *user)
{
    struct passwd *pwd;
    int ngroups;
    gid_t *groups;

    /* Look up user in user database (usually /etc/passwd) to get UID/GID */
    pwd = getpwnam(user);
    if (pwd == NULL) {
        fprintf(stderr, "Unknown user: %s\n", user);
        exit(EXIT_FAILURE);
    }

    /* * Find out how many supplementary groups the user is a member of.
     * By passing NULL for the list and pointer to 0 for ngroups, 
     * getgrouplist fills ngroups with the required size.
     */
    ngroups = 0;
    getgrouplist(user, pwd->pw_gid, NULL, &ngroups);

    /* Allocate an array for supplementary group IDs based on the count found */
    groups = calloc(ngroups, sizeof(gid_t));
    if (groups == NULL)
        errExit("calloc");

    /* Get the actual supplementary group list of 'user' from group database */
    if (getgrouplist(user, pwd->pw_gid, groups, &ngroups) == -1)
        errExit("getgrouplist");

    /* Set the supplementary group list for the current process */
    if (setgroups(ngroups, groups) == -1)
        errExit("setgroups");

    /* * Set Real, Effective, and Saved Group IDs to the GID of the target user.
     * This fully drops root group privileges.
     */
    if (setresgid(pwd->pw_gid, pwd->pw_gid, pwd->pw_gid) == -1)
        errExit("setresgid");

    /* * Set Real, Effective, and Saved User IDs to the UID of the target user.
     * This fully drops root user privileges.
     */
    if (setresuid(pwd->pw_uid, pwd->pw_uid, pwd->pw_uid) == -1)
        errExit("setresuid");
}

/* Add a set of capabilities to the process's ambient list */
static void
setAmbientCapabilities(char *capList)
{
    cap_value_t cap;

    /* Walk through the capabilities listed in the comma-delimited list
       of capability names in 'capList', adding each capability to the
       ambient set. This will cause the capability to pass into the
       process permitted and effective sets during exec(). */

    for (char *p = capList; (p = strtok(p, ",")); p = NULL) {

        /* Convert the capability name (e.g., "cap_net_bind_service") to a 
           capability number (integer ID used by kernel) */
        if (cap_from_name(p, &cap) == -1) {
            fprintf(stderr, "Unrecognized capability name: %s\n", p);
            exit(EXIT_FAILURE);
        }

        /* * Rule of Ambient Caps: A capability cannot be raised in the Ambient set
         * unless it is ALREADY present in the Inheritable set.
         * * modifyCapSetting is the helper function from cap_functions.c.
         * It sets the bit in the Inheritable set.
         */
        if (modifyCapSetting(CAP_INHERITABLE, cap, CAP_SET) == -1) {
            fprintf(stderr, "Could not raise '%s' inheritable "
                    "capability (%s)\n", p, strerror(errno));
            exit(EXIT_FAILURE);
        }

        /* * Raise the capability in the ambient set using prctl().
         * PR_CAP_AMBIENT_RAISE ensures the capability survives the execve() 
         * call that follows later, allowing the non-root child process to have it.
         */
        if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0) == -1) {
            fprintf(stderr, "Could not raise '%s' ambient "
                    "capability (%s)\n", p, strerror(errno));
            exit(EXIT_FAILURE);
        }
    }
}

int
main(int argc, char *argv[])
{
    /* Validate command line arguments */
    if (argc < 4 || strcmp(argv[1], "--help") == 0)
        usage(argv[0]);

    /* This program must start as root to switch UIDs and manipulate capability sets */
    if (geteuid() != 0)
        fatal("Must be run as root");

    /* * Set "no setuid fixup" securebit.
     * Normally, when a process switches UID from 0 to non-zero, the kernel clears 
     * the capability sets. Setting this bit prevents that clearing, allowing us 
     * to retain the capabilities we want to pass to the user.
     */
    if (prctl(PR_SET_SECUREBITS, SECBIT_NO_SETUID_FIXUP, 0, 0, 0) == -1)
        errExit("prctl");

    /* Drop privileges to the specified user */
    setCredentials(argv[1]);

    /* Configure the ambient capabilities requested */
    setAmbientCapabilities(argv[2]);

    /* * Execute the program (with arguments) named in argv[3]... 
     * Because of the ambient capabilities set above, the new program 
     * will start with those capabilities active, even though it is running 
     * as a non-root user.
     */
    execvp(argv[3], &argv[3]);
    errExit("execvp");
}


