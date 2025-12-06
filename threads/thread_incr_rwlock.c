/*************************************************************************\
* Copyright (C) Michael Kerrisk, 2019.                   *
* *
* This program is free software. You may use, modify, and redistribute it *
* under the terms of the GNU General Public License as published by the   *
* Free Software Foundation, either version 3 or (at your option) any      *
* later version. This program is distributed without any warranty.  See   *
* the file COPYING.gpl-v3 for details.                                    *
\*************************************************************************/

/* Supplementary program for Chapter 33 */

/* thread_incr_rwlock.c

   This program employs two POSIX threads that increment the same global
   variable, synchronizing their access using a read/write lock. As a
   consequence, updates are not lost. Compare with thread_incr.c,
   thread_incr_mutex.c, and thread_incr_spinlock.c.
*/

/*
 * VERBOSE COMMENTARY:
 * * Concept: Read-Write Locks (rwlock)
 * Standard mutexes allow only ONE thread access at a time.
 * Read-Write locks distinguish between:
 * 1. Readers: Multiple threads can hold a "read lock" simultaneously (shared).
 * 2. Writers: Only ONE thread can hold a "write lock" (exclusive).
 * * If a writer holds the lock, no one else (reader or writer) can enter.
 * * Note on this specific example:
 * Since both threads here are WRITERS (they increment 'glob'), this program 
 * operates almost identically to a standard Mutex. The benefit of rwlocks 
 * appears when you have many readers and few writers.
 */

#include <pthread.h>
#include "tlpi_hdr.h"

static volatile int glob = 0;
static pthread_rwlock_t rwlock; /* The Read-Write Lock Object */

static void * /* Loop 'arg' times incrementing 'glob' */
threadFunc(void *arg)
{
    int loops = *((int *) arg);
    int loc, s;

    for (int j = 0; j < loops; j++) {
        
        /* * Acquire Write Lock.
         * Because we are modifying 'glob', we need EXCLUSIVE access.
         * pthread_rwlock_wrlock() blocks until there are NO readers 
         * and NO other writers holding the lock.
         */
        s = pthread_rwlock_wrlock(&rwlock);
        if (s != 0)
            errExitEN(s, "pthread_rwlock_wrlock");

        /* Critical Section: Read, Modify, Write */
        loc = glob;
        loc++;
        glob = loc;

        /* Release the lock so others can proceed */
        s = pthread_rwlock_unlock(&rwlock);
        if (s != 0)
            errExitEN(s, "pthread_rwlock_unlock");
    }

    return NULL;
}

int
main(int argc, char *argv[])
{
    pthread_t t1, t2;
    int loops, s;

    loops = (argc > 1) ? getInt(argv[1], GN_GT_0, "num-loops") : 10000000;

    /* * Initialize the Read-Write Lock.
     * The second argument (NULL or 0) specifies default attributes.
     */
    s = pthread_rwlock_init(&rwlock, 0);
    if (s != 0)
        errExitEN(s, "pthread_rwlock_init");

    /* Create two threads that will fight for the write lock */
    s = pthread_create(&t1, NULL, threadFunc, &loops);
    if (s != 0)
        errExitEN(s, "pthread_create");
    s = pthread_create(&t2, NULL, threadFunc, &loops);
    if (s != 0)
        errExitEN(s, "pthread_create");

    /* Wait for threads to finish */
    s = pthread_join(t1, NULL);
    if (s != 0)
        errExitEN(s, "pthread_join");
    s = pthread_join(t2, NULL);
    if (s != 0)
        errExitEN(s, "pthread_join");

    printf("glob = %d\n", glob);
    exit(EXIT_SUCCESS);
}


