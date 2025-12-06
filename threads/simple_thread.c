/*************************************************************************\
* Copyright (C) Michael Kerrisk, 2019.                   *
* *
* This program is free software. You may use, modify, and redistribute it *
* under the terms of the GNU General Public License as published by the   *
* Free Software Foundation, either version 3 or (at your option) any      *
* later version. This program is distributed without any warranty.  See   *
* the file COPYING.gpl-v3 for details.                                    *
\*************************************************************************/

/* Listing 29-1 */

/* simple_thread.c

   A simple POSIX threads example: create a thread, and then join with it.
*/

/* * VERBOSE COMMENTARY:
 * This program demonstrates the "Hello World" of threading.
 * It spawns a single new thread, passes a string argument to it,
 * waits for it to finish, and retrieves a return value (the length of the string).
 */

#include <pthread.h>  /* Required for POSIX threads API */
#include "tlpi_hdr.h" /* Standard header for this book's examples (error handling, types) */

/*
 * threadFunc
 * ----------
 * This is the start routine for the new thread.
 * * arg: A generic void pointer passed from pthread_create. 
 * In this case, it points to the string "Hello world\n".
 * * Returns: A void pointer representing the result of the thread.
 * Here, we cast the integer length of the string to (void *).
 */
static void *
threadFunc(void *arg)
{
    /* Cast the void pointer back to a char pointer to use it as a string */
    char *s = (char *) arg;

    /* Print the string passed from the main thread */
    printf("%s", s);

    /* * Return the length of the string. 
     * Note: We are casting a 'size_t' (integer) to 'void *' to return it.
     * This is a common pattern for returning simple integers, though strictly 
     * speaking, one should be careful about the size of integer vs size of pointer.
     */
    return (void *) strlen(s);
}

int
main(int argc, char *argv[])
{
    pthread_t t1;   /* Variable to hold the ID of the newly created thread */
    void *res;      /* Pointer to hold the return value from the thread */
    int s;          /* Status variable for API return codes */

    /*
     * pthread_create
     * --------------
     * Creates a new thread.
     * * &t1:          Pointer to the pthread_t variable to store the new thread's ID.
     * NULL:         Thread attributes. NULL means use default attributes.
     * threadFunc:   The function the new thread will begin executing.
     * "Hello...":   The argument passed to threadFunc.
     */
    s = pthread_create(&t1, NULL, threadFunc, "Hello world\n");
    if (s != 0)
        errExitEN(s, "pthread_create"); /* Check for errors (e.g., resource limits) */

    printf("Message from main()\n");

    /*
     * pthread_join
     * ------------
     * Blocks the calling thread (main) until the specified thread (t1) terminates.
     * This is similar to waitpid() for processes.
     *
     * t1:   The thread to wait for.
     * &res: A pointer to a void pointer. The return value of threadFunc 
     * will be stored here.
     */
    s = pthread_join(t1, &res);
    if (s != 0)
        errExitEN(s, "pthread_join");

    /* * Cast the result (void *) back to long/integer to print it.
     * We expect the length of "Hello world\n" (12).
     */
    printf("Thread returned %ld\n", (long) res);

    exit(EXIT_SUCCESS);
}
