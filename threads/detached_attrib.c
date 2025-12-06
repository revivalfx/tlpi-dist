/*************************************************************************\
* Copyright (C) Michael Kerrisk, 2019.                   *
* *
* This program is free software. You may use, modify, and redistribute it *
* under the terms of the GNU General Public License as published by the   *
* Free Software Foundation, either version 3 or (at your option) any      *
* later version. This program is distributed without any warranty.  See   *
* the file COPYING.gpl-v3 for details.                                    *
\*************************************************************************/

/* Listing 29-2 */

/* detached_attrib.c

   An example of the use of POSIX thread attributes (pthread_attr_t):
   creating a detached thread.
*/

/*
 * VERBOSE COMMENTARY:
 * By default, threads are "joinable". This means you must call pthread_join() 
 * to release their resources (thread ID, stack, exit status) after they finish.
 * If you don't join, you get a resource leak (a "zombie thread").
 * * A "detached" thread automatically releases its resources when it terminates.
 * However, you cannot call pthread_join() on a detached thread.
 */

#include <pthread.h>
#include "tlpi_hdr.h"

/* A simple thread function that just returns the argument passed to it */
static void *
threadFunc(void *x)
{
    return x;
}

int
main(int argc, char *argv[])
{
    pthread_t thr;          /* Thread ID */
    pthread_attr_t attr;    /* Object to hold thread attributes */
    int s;

    /*
     * Initialize the attribute object with default values.
     * This must be done before setting specific attributes.
     */
    s = pthread_attr_init(&attr);       /* Assigns default values */
    if (s != 0)
        errExitEN(s, "pthread_attr_init");

    /*
     * Set the "detach state" attribute to DETACHED.
     * This tells the system: "When this thread is created, mark it as detached immediately."
     */
    s = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (s != 0)
        errExitEN(s, "pthread_attr_setdetachstate");

    /*
     * Create the thread using the custom attributes object (&attr).
     */
    s = pthread_create(&thr, &attr, threadFunc, (void *) 1);
    if (s != 0)
        errExitEN(s, "pthread_create");

    /*
     * Destroy the attribute object. 
     * Once the thread is created, the attribute object is no longer needed 
     * by the thread (the settings are copied into the thread).
     * This frees any memory associated with the attribute object itself.
     */
    s = pthread_attr_destroy(&attr);    /* No longer needed */
    if (s != 0)
        errExitEN(s, "pthread_attr_destroy");

    /*
     * Attempt to join the thread.
     * Because the thread was created as DETACHED, this call MUST fail.
     * The system returns EINVAL (Invalid argument) because the thread is not joinable.
     */
    s = pthread_join(thr, NULL);
    if (s != 0)
        errExitEN(s, "pthread_join failed as expected");

    exit(EXIT_SUCCESS);
}

