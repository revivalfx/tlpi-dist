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

/* t_cap_get_file.c

   Display the capabilities attached to a file.
*/
#include <sys/capability.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
                        } while (0)

int
main(int argc, char *argv[])
{
    cap_t caps;
    char *str;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <pathname>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    /* Fetch and display file capabilities */

    /* * cap_get_file(path) retrieves the capabilities associated with the file 
     * at 'path'. These are stored in the 'security.capability' extended attribute.
     */
    caps = cap_get_file(argv[1]);

    if (caps == NULL) {
        /* * ENODATA indicates that the extended attribute "security.capability"
         * is not present on the file. This is the normal state for most files.
         */
        if (errno == ENODATA)
            printf("No capabilities are attached to this file\n");
        else
            errExit("cap_get_file");
    } else {
        /* Convert the internal capability structure to a human-readable string */
        str = cap_to_text(caps, NULL);
        if (str == NULL)
            errExit("cap_to_text");

        printf("Capabilities: %s\n", str);

        /* Free the text string memory */
        cap_free(str);
    }

    /* Free the capability structure memory */
    cap_free(caps);

    exit(EXIT_SUCCESS);
}


