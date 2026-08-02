#ifndef __RANDOMBYTES_H
#define __RANDOMBYTES_H

#include <stddef.h>

void randombytes(void *ptr, size_t length);
/** Fill buffer with OS entropy. Returns 1 on success, 0 on failure (no exit). */
int randombytes_try(void *ptr, size_t length);
void srandom_init(void);

#endif
