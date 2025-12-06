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

/* view_cap_xattr.c

   Display the contents of the "security.capability" extended attribute
   of a file. This attribute is used to store the capabilities associated
   with a file.
*/
#include <sys/xattr.h>          /* For getxattr() */
#include <sys/capability.h>
#include <linux/capability.h>   /* Defines 'struct vfs_ns_cap_data' and
                                   VFS_CAP_* constants for raw data layout */
#include "tlpi_hdr.h"

int
main(int argc, char *argv[])
{
    /* * struct vfs_ns_cap_data represents the raw binary layout of the capability 
     * data stored in the extended attribute.
     */
    struct vfs_ns_cap_data cap_data;
    ssize_t valueLen;

    if (argc != 2 || strcmp(argv[1], "--help") == 0)
        usageErr("%s <file>\n", argv[0]);

    /* * Retrieve the extended attribute named "security.capability".
     * We read the raw bytes directly into the 'cap_data' structure.
     */
    valueLen = getxattr(argv[1], "security.capability",
                        (char *) &cap_data, sizeof(cap_data));
    if (valueLen == -1) {
        if (errno == ENODATA)
            fatal("\"%s\" has no \"security.capability\" attribute", argv[1]);
        else
            errExit("getxattr");
    }

    /* * The first field, magic_etc, contains both the version number and the 
     * effective bit flag. We shift right to extract the version.
     */
    printf("Capability version: %d",
            cap_data.magic_etc >> VFS_CAP_REVISION_SHIFT);

    /* Only version 3 capabilities (VFS_CAP_REVISION_3) have the 'rootid' field. 
       This version is used for namespaced file capabilities. */
    if ((cap_data.magic_etc & VFS_CAP_REVISION_MASK) == VFS_CAP_REVISION_3)
        printf("   [root ID = %u]", cap_data.rootid);

    printf("\n");

    /* The size of the returned attribute value depends on the version of
       the 'security.capability' extended attribute */
    printf("Length of returned value = %ld\n", (long) valueLen);

    /* Display file capabilities details */

    /* Check the effective bit flag. In file caps, 'effective' is just a single bit,
       not a full set. If set, the permitted caps are automatically moved to effective
       upon execution. */
    printf("    Effective bit:   %d\n",
            cap_data.magic_etc & VFS_CAP_FLAGS_EFFECTIVE);

    /* * Display the Permitted set.
     * The data array holds 32-bit chunks. data[0] is bits 0-31, data[1] is bits 32-63.
     */
    printf("    Permitted set:   %08x %08x\n",
            cap_data.data[1].permitted, cap_data.data[0].permitted);

    /* Display the Inheritable set. */
    printf("    Inheritable set: %08x %08x\n",
            cap_data.data[1].inheritable, cap_data.data[0].inheritable);
    exit(EXIT_SUCCESS);
}


