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

/* thread_incr_spinlock.c

   This program employs two POSIX threads that increment the same global
   variable, synchronizing their access using a spinlock. As a consequence,
   updates are not lost. Compare with thread_incr.c, thread_incr_mutex.c,
   and thread_incr_rwlock.c
*/

/*
 * VERBOSE COMMENTARY:
 * * Concept: Spinlocks
 * A Mutex puts a thread to sleep (context switch) if the lock is busy. 
 * This saves CPU but incurs the overhead of the context switch (slow).
 * * A Spinlock does NOT put the thread to sleep. It sits in a tight loop 
 * (busy waiting) repeatedly checking if the lock is available.
 * * When to use:
 * - If the Critical Section is VERY short (shorter than the time it takes 
 * to context switch).
 * - On multi-core systems (on a single core, spinning is wasteful because 
 * you block the thread that actually holds the lock).
 */

#include <pthread.h>
#include "tlpi_hdr.h"

static volatile int glob = 0;
static pthread_spinlock_t splock; /* The Spinlock Object */

static void * /* Loop 'arg' times incrementing 'glob' */
threadFunc(void *arg)
{
    int loops = *((int *) arg);
    int loc, s;

    for (int j = 0; j < loops; j++) {
        
        /* * Acquire Spinlock.
         * If 'splock' is locked by another thread, this function will loop 
         * continuously (burning CPU cycles) until the lock is released.
         */
        s = pthread_spin_lock(&splock);
        if (s != 0)
            errExitEN(s, "pthread_spin_lock");

        /* Critical Section */
        loc = glob;
        loc++;
        glob = loc;

        /* Release Spinlock */
        s = pthread_spin_unlock(&splock);
        if (s != 0)
            errExitEN(s, "pthread_spin_unlock");
    }

    return NULL;
}

int
main(int argc, char *argv[])
{
    pthread_t t1, t2;
    int loops, s;

    loops = (argc > 1) ? getInt(argv[1], GN_GT_0, "num-loops") : 10000000;

    /*
     * Initialize the Spinlock.
     * The second argument (pshared) determines if the lock is shared between processes.
     * 0 = Thread Shared (Private to this process).
     * PTHREAD_PROCESS_SHARED = Shared between different processes (requires shared memory).
     */
    s = pthread_spin_init(&splock, 0);
    if (s != 0)
        errExitEN(s, "pthread_spin_init");

    /* Create threads */
    s = pthread_create(&t1, NULL, threadFunc, &loops);
    if (s != 0)
        errExitEN(s, "pthread_create");
    s = pthread_create(&t2, NULL, threadFunc, &loops);
    if (s != 0)
        errExitEN(s, "pthread_create");

    /* Join threads */
    s = pthread_join(t1, NULL);
    if (s != 0)
        errExitEN(s, "pthread_join");
    s = pthread_join(t2, NULL);
    if (s != 0)
        errExitEN(s, "pthread_join");

    printf("glob = %d\n", glob);
    exit(EXIT_SUCCESS);
}

