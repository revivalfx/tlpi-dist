/*************************************************************************\
* Copyright (C) Michael Kerrisk, 2019.                   *
* *
* This program is free software. You may use, modify, and redistribute it *
* under the terms of the GNU Lesser General Public License as published   *
* by the Free Software Foundation, either version 3 or (at your option)   *
* any later version. This program is distributed without any warranty.    *
* See the files COPYING.lgpl-v3 and COPYING.gpl-v3 for details.           *
\*************************************************************************/

/* Supplementary program for Chapter 39 */

/* cap_functions.c

   Useful functions for working with capabilities.
*/

#include <stdio.h>
#include "cap_functions.h"

/* Change the 'setting' of the specified 'capability' in the capability set
   specified by 'flag'.

   'flag' is one of CAP_PERMITTED, CAP_EFFECTIVE, or CAP_INHERITABLE.
   'setting' is one of CAP_SET (enable) or CAP_CLEAR (disable).

   Returns: 0 on success or -1 on error. */

int
modifyCapSetting(cap_flag_t flag, int capability, int setting)
{
    /* Opaque pointer for holding the process's capability state */
    cap_t caps;
    
    /* * Array to hold the capability values we want to modify.
     * Even though we are only modifying one capability here, the API expects an array.
     */
    cap_value_t capList[1];

    /* Retrieve caller's current capabilities 
     * cap_get_proc() allocates a cap_t structure populated with the 
     * current process's capabilities.
     */
    caps = cap_get_proc();
    if (caps == NULL)
        return -1;

    /* Change setting of 'capability' in the 'flag' capability set in 'caps'.
       The third argument, 1, is the number of items in the array 'capList'. */

    /* Prepare the list with the specific capability ID passed to the function */
    capList[0] = capability;

    /* * cap_set_flag modifies the internal representation 'caps'.
     * It does NOT apply changes to the kernel yet.
     * * Arguments:
     * 1. caps: The capability state structure.
     * 2. flag: Which set to modify (Permitted, Effective, Inheritable).
     * 3. 1: The number of capabilities in the list.
     * 4. capList: The array containing the capability IDs.
     * 5. setting: CAP_SET (to raise) or CAP_CLEAR (to lower).
     */
    if (cap_set_flag(caps, flag, 1, capList, setting) == -1) {
        cap_free(caps); /* Clean up memory on failure */
        return -1;
    }

    /* Push modified capability sets back to kernel, to change
       caller's capabilities.
       
       cap_set_proc() takes the modified 'caps' structure and applies it 
       to the running process via a system call. This is where the permission 
       check happens.
    */
    if (cap_set_proc(caps) == -1) {
        cap_free(caps);
        return -1;
    }

    /* Free the structure that was allocated by cap_get_proc() to prevent memory leaks */
    if (cap_free(caps) == -1)
        return -1;

    return 0;
}


