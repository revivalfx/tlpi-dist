/*************************************************************************\
* Copyright (C) Michael Kerrisk, 2019.                   *
* *
* This program is free software. You may use, modify, and redistribute it *
* under the terms of the GNU General Public License as published by the   *
* Free Software Foundation, either version 3 or (at your option) any      *
* later version. This program is distributed without any warranty.  See   *
* the file COPYING.gpl-v3 for details.                                    *
\*************************************************************************/

/* Listing 30-2 */

/* thread_incr_mutex.c

   This program employs two POSIX threads that increment the same global
   variable, synchronizing their access using a mutex. As a consequence,
   updates are not lost. Compare with thread_incr.c, thread_incr_spinlock.c,
   and thread_incr_rwlock.c.
*/

/*
 * VERBOSE COMMENTARY:
 * This file fixes the race condition in thread_incr.c.
 * It uses a mutex to ensure that only ONE thread can be inside the 
 * Read-Modify-Write block at any given time.
 */

#include <pthread.h>
#include "tlpi_hdr.h"

static volatile int glob = 0;

/* * Define a mutex initialized to the default state (unlocked).
 * Only one thread can hold this lock at a time.
 */
static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;

static void * /* Loop 'arg' times incrementing 'glob' */
threadFunc(void *arg)
{
    int loops = *((int *) arg);
    int loc, j, s;

    for (j = 0; j < loops; j++) {
        /* * LOCK THE MUTEX
         * If the mutex is already locked by another thread, this call BLOCKS (sleeps)
         * until the mutex becomes available.
         */
        s = pthread_mutex_lock(&mtx);
        if (s != 0)
            errExitEN(s, "pthread_mutex_lock");

        /* * CRITICAL SECTION START
         * We now have exclusive access to 'glob'. No other thread can touch it
         * because they are stuck waiting at pthread_mutex_lock.
         */
        loc = glob;
        loc++;
        glob = loc;
        /* CRITICAL SECTION END */

        /* * UNLOCK THE MUTEX
         * This releases the lock. If other threads are waiting, one of them
         * will be woken up to acquire the lock.
         */
        s = pthread_mutex_unlock(&mtx);
        if (s != 0)
            errExitEN(s, "pthread_mutex_unlock");
    }

    return NULL;
}

int
main(int argc, char *argv[])
{
    pthread_t t1, t2;
    int loops, s;

    loops = (argc > 1) ? getInt(argv[1], GN_GT_0, "num-loops") : 10000000;

    s = pthread_create(&t1, NULL, threadFunc, &loops);
    if (s != 0)
        errExitEN(s, "pthread_create");
    s = pthread_create(&t2, NULL, threadFunc, &loops);
    if (s != 0)
        errExitEN(s, "pthread_create");

    s = pthread_join(t1, NULL);
    if (s != 0)
        errExitEN(s, "pthread_join");
    s = pthread_join(t2, NULL);
    if (s != 0)
        errExitEN(s, "pthread_join");

    /* With the mutex, the output will effectively be exactly 2 * loops */
    printf("glob = %d\n", glob);
    exit(EXIT_SUCCESS);
}

