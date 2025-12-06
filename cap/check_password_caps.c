/*************************************************************************\
* Copyright (C) Michael Kerrisk, 2019.                   *
* *
* This program is free software. You may use, modify, and redistribute it *
* under the terms of the GNU General Public License as published by the   *
* Free Software Foundation, either version 3 or (at your option) any      *
* later version. This program is distributed without any warranty.  See   *
* the file COPYING.gpl-v3 for details.                                    *
\*************************************************************************/

/* Listing 39-1 */

/* check_password_caps.c

   This program provides an example of the use of capabilities to create a
   program that performs a task that requires privileges, but operates without
   the full power of 'root'. The program reads a username and password and
   checks if they are valid by authenticating against the (shadow) password
   file.

   The program executable file must be installed with the CAP_DAC_READ_SEARCH
   permitted capability, as follows:

        $ sudo setcap "cap_dac_read_search=p" check_password_caps

   This program is Linux-specific.

   See also check_password.c.
*/
#define _BSD_SOURCE             /* Get getpass() declaration from <unistd.h> */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE           /* Get crypt() declaration from <unistd.h> */
#endif
#include <sys/capability.h>
#include <unistd.h>
#include <limits.h>
#include <pwd.h>
#include <shadow.h>
#include "tlpi_hdr.h"

/* Change setting of capability in caller's effective capabilities */
static int
modifyCap(int capability, int setting)
{
    cap_t caps;
    cap_value_t capList[1];

    /* Retrieve caller's current capabilities into 'caps' structure */
    caps = cap_get_proc();
    if (caps == NULL)
        return -1;

    /* Change setting of 'capability' in the effective set of 'caps'. 
       We target CAP_EFFECTIVE because that is the set checked by the kernel
       when performing permission checks. 
       The third argument, 1, is the number of items in the array 'capList'. */
    capList[0] = capability;
    if (cap_set_flag(caps, CAP_EFFECTIVE, 1, capList, setting) == -1) {
        cap_free(caps);
        return -1;
    }

    /* Push modified capability sets back to kernel, to change
       caller's capabilities immediately. */
    if (cap_set_proc(caps) == -1) {
        cap_free(caps);
        return -1;
    }

    /* Free the structure that was allocated by libcap */
    if (cap_free(caps) == -1)
        return -1;

    return 0;
}

static int              /* Raise capability in caller's effective set */
raiseCap(int capability)
{
    /* Use helper to Set (enable) the capability */
    return modifyCap(capability, CAP_SET);
}

/* An analogous dropCap() (unneeded in this program), could be
   defined as: modifyCap(capability, CAP_CLEAR); */

static int              /* Drop all capabilities from all sets */
dropAllCaps(void)
{
    cap_t empty;
    int s;

    /* Initialize an empty capability set (all capabilities cleared) */
    empty = cap_init();
    if (empty == NULL)
        return -1;

    /* Apply the empty set to the process, effectively stripping all privileges */
    s = cap_set_proc(empty);

    if (cap_free(empty) == -1)
        return -1;

    return s;
}

int
main(int argc, char *argv[])
{
    char *username, *password, *encrypted, *p;
    struct passwd *pwd;
    struct spwd *spwd;
    Boolean authOk;
    size_t len;
    long lnmax;

    /* Determine size of buffer required for a username, and allocate it */
    lnmax = sysconf(_SC_LOGIN_NAME_MAX);
    if (lnmax == -1)                        /* If limit is indeterminate */
        lnmax = 256;                        /* make a guess */

    username = malloc(lnmax);
    if (username == NULL)
        errExit("malloc");

    printf("Username: ");
    fflush(stdout);
    if (fgets(username, lnmax, stdin) == NULL)
        exit(EXIT_FAILURE);                 /* Exit on EOF */

    /* Strip newline character from input */
    len = strlen(username);
    if (username[len - 1] == '\n')
        username[len - 1] = '\0';           /* Remove trailing '\n' */

    /* Look up password record for username (standard /etc/passwd info) */
    pwd = getpwnam(username);
    if (pwd == NULL)
        fatal("couldn't get password record");

    /* * KEY STEP: Raise CAP_DAC_READ_SEARCH.
     * We need this capability specifically to read /etc/shadow, which is 
     * usually readable only by root (or shadow group).
     * We only raise it right before we need it.
     */
    if (raiseCap(CAP_DAC_READ_SEARCH) == -1)
        fatal("raiseCap() failed");

    /* Look up shadow password record for username. This reads /etc/shadow. */
    spwd = getspnam(username);
    if (spwd == NULL && errno == EACCES)
        fatal("no permission to read shadow password file");

    /* * KEY STEP: Drop privileges.
     * At this point, we have the shadow record in memory. We don't need 
     * high privileges anymore, so we drop ALL capabilities for safety.
     */
    if (dropAllCaps() == -1)
        fatal("dropAllCaps() failed");

    if (spwd != NULL)           /* If there is a shadow password record */
        pwd->pw_passwd = spwd->sp_pwdp;     /* Use the shadow password */

    /* Read password from user (disables echo) */
    password = getpass("Password: ");

    /* Encrypt password and erase cleartext version immediately */
    /* Note: modern systems usually use crypt_r, but this is a demo */
    encrypted = crypt(password, pwd->pw_passwd);
    
    /* Zero out the plaintext password in memory for security */
    for (p = password; *p != '\0'; )
        *p++ = '\0';

    if (encrypted == NULL)
        errExit("crypt");

    /* Compare the newly encrypted input with the stored hash */
    authOk = strcmp(encrypted, pwd->pw_passwd) == 0;
    if (!authOk) {
        printf("Incorrect password\n");
        exit(EXIT_FAILURE);
    }

    printf("Successfully authenticated: UID=%ld\n", (long) pwd->pw_uid);

    /* Now do authenticated work... */

    exit(EXIT_SUCCESS);
}


