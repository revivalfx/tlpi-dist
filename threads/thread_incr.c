/*************************************************************************\
* Copyright (C) Michael Kerrisk, 2019.                   *
* *
* This program is free software. You may use, modify, and redistribute it *
* under the terms of the GNU General Public License as published by the   *
* Free Software Foundation, either version 3 or (at your option) any      *
* later version. This program is distributed without any warranty.  See   *
* the file COPYING.gpl-v3 for details.                                    *
\*************************************************************************/

/* Listing 30-1 */

/* thread_incr.c

   This program employs two POSIX threads that increment the same global
   variable, without using any synchronization method. As a consequence,
   updates are sometimes lost.

   See also thread_incr_mutex.c.
*/

/*
 * VERBOSE COMMENTARY:
 * This is a classic demonstration of why we need locking.
 * Two threads run a loop. Each loop iteration does:
 * 1. Read global variable 'glob' into a CPU register.
 * 2. Add 1 to the register.
 * 3. Write the register value back to 'glob'.
 * * Without locking, Thread A can Read (val 0), then Thread B Reads (val 0),
 * Thread A adds 1 and writes (glob = 1), Thread B adds 1 to its old read (0) 
 * and writes (glob = 1). We did two increments, but the result is 1, not 2.
 * This is a "Lost Update".
 */

#include <pthread.h>
#include "tlpi_hdr.h"

/* * 'volatile' tells the compiler NOT to optimize this variable.
 * Without volatile, the compiler might keep 'glob' in a register for the 
 * entire loop, effectively hiding the race condition. We want to force 
 * the CPU to go to memory so the race condition is visible.
 */
static volatile int glob = 0;   /* "volatile" prevents compiler optimizations
                                   of arithmetic operations on 'glob' */

static void * /* Loop 'arg' times incrementing 'glob' */
threadFunc(void *arg)
{
    int loops = *((int *) arg); /* Number of increments to perform */
    int loc, j;

    for (j = 0; j < loops; j++) {
        /* * The Read-Modify-Write cycle (Critical Section - UNPROTECTED).
         * If a context switch happens between these lines, the state becomes inconsistent.
         */
        loc = glob;     /* Fetch */
        loc++;          /* Increment */
        glob = loc;     /* Store */
    }

    return NULL;
}

int
main(int argc, char *argv[])
{
    pthread_t t1, t2;
    int loops, s;

    /* Get number of loops from command line, default to 10,000,000 */
    loops = (argc > 1) ? getInt(argv[1], GN_GT_0, "num-loops") : 10000000;

    /* Create two threads running the same function */
    s = pthread_create(&t1, NULL, threadFunc, &loops);
    if (s != 0)
        errExitEN(s, "pthread_create");
    s = pthread_create(&t2, NULL, threadFunc, &loops);
    if (s != 0)
        errExitEN(s, "pthread_create");

    /* Wait for both to finish */
    s = pthread_join(t1, NULL);
    if (s != 0)
        errExitEN(s, "pthread_join");
    s = pthread_join(t2, NULL);
    if (s != 0)
        errExitEN(s, "pthread_join");

    /* * Print the final value.
     * If synchronization were correct, glob would equal 2 * loops.
     * Because of the race condition, it will likely be significantly lower.
     */
    printf("glob = %d\n", glob);
    exit(EXIT_SUCCESS);
}


