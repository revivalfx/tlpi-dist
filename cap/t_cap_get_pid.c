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

/* t_cap_get_pid.c

   Display the capabilities of a process with specified PID.
*/

/* * Include necessary headers:
 * <sys/capability.h>: Required for all libcap functions (cap_get_pid, cap_to_text, etc.).
 * <unistd.h>, <stdio.h>, <stdlib.h>: Standard POSIX and C library functions.
 */
#include <sys/capability.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

/* * Macro for error handling. 
 * perror(msg) prints the error message provided, followed by a description 
 * of the current value of errno. 
 * exit(EXIT_FAILURE) terminates the program with a non-zero status.
 */
#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
                        } while (0)

int
main(int argc, char *argv[])
{
    /* 'caps' is a pointer to an opaque structure used by libcap to represent capabilities. */
    cap_t caps;
    /* 'str' will hold the textual representation of the capabilities. */
    char *str;

    /* Check if the user provided a PID argument. */
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    /* Fetch and display process capabilities */

    /* * cap_get_pid(pid) retrieves the capabilities of the process identified by 'pid'.
     * atoi(argv[1]) converts the command-line string argument to an integer.
     * * If successful, it returns a cap_t (pointer). 
     * If it returns NULL, the call failed (e.g., PID doesn't exist or permission denied).
     */
    caps = cap_get_pid(atoi(argv[1]));
    if (caps == NULL)
        errExit("cap_get_pid");

    /* * cap_to_text(caps, len_p) converts the internal capability representation 'caps'
     * into a human-readable string.
     * * The second argument (NULL here) can be a pointer to a ssize_t to receive the length 
     * of the string. Passing NULL means we don't need the length.
     * * The format of the string is compatible with cap_from_text() and setcap/getcap tools.
     * Example output: "cap_net_admin,cap_sys_time=ep"
     */
    str = cap_to_text(caps, NULL);
    if (str == NULL)
        errExit("cap_to_text");

    /* Print the resulting capability string to stdout. */
    printf("Capabilities: %s\n", str);

    /* * Memory cleanup is crucial in C.
     * cap_free() is used to release memory allocated by libcap functions.
     * We must free the 'caps' structure allocated by cap_get_pid().
     */
    cap_free(caps);
    
    /* We must also free the string allocated by cap_to_text(). */
    cap_free(str);

    exit(EXIT_SUCCESS);
}


