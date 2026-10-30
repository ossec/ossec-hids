/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Common API for dealing with hashes/maps */

#include "shared.h"

/* Largest prime below 2^32: the hash is a polynomial over this field */
#define OSHASH_PRIME 4294967291U

static int _os_genseed(OSHash *self) __attribute__((nonnull));
static unsigned int _os_genhash(const OSHash *self, const char *key) __attribute__((nonnull));

/* Choose the (secret) seed and multiplier of the hash.
 * Returns 1 on success, 0 if no entropy is available (do not fall back to
 * a time-based seed: that would let an attacker prepare collisions).
 * Programs that chroot must call srandom_init() before creating tables.
 */
static int _os_genseed(OSHash *self)
{
    unsigned int secret[2];

    if (!randombytes_try(secret, sizeof(secret))) {
        return (0);
    }

    self->initial_seed = secret[0] % OSHASH_PRIME;
    self->constant = 256 + (secret[1] % (OSHASH_PRIME - 256));
    return (1);
}


/* Create hash
 * Returns NULL on error
 */
OSHash *OSHash_Create()
{
    unsigned int i = 0;
    OSHash *self;

    /* Allocate memory for the hash */
    self = (OSHash *) calloc(1, sizeof(OSHash));
    if (!self) {
        return (NULL);
    }

    /* Set default row size */
    self->rows = os_getprime(1024);
    if (self->rows == 0) {
        free(self);
        return (NULL);
    }

    /* Create hashing table */
    self->table = (OSHashNode **)calloc(self->rows + 1, sizeof(OSHashNode *));
    if (!self->table) {
        free(self);
        return (NULL);
    }

    /* Zero our tables */
    for (i = 0; i <= self->rows; i++) {
        self->table[i] = NULL;
    }

    /* Get seed */
    if (!_os_genseed(self)) {
        free(self->table);
        free(self);
        return (NULL);
    }

    return (self);
}

/* Free the memory used by the hash */
void *OSHash_Free(OSHash *self)
{
    unsigned int i = 0;
    OSHashNode *curr_node;
    OSHashNode *next_node;

    /* Free each entry */
    while (i <= self->rows) {
        curr_node = self->table[i];
        next_node = curr_node;
        while (next_node) {
            next_node = next_node->next;
            free(curr_node->key);
            free(curr_node);
            curr_node = next_node;
        }
        i++;
    }

    /* Free the hash table */
    free(self->table);

    free(self);
    return (NULL);
}

/* Generates hash for key */
static unsigned int _os_genhash(const OSHash *self, const char *key)
{
    unsigned long long hash_key = self->initial_seed;

    /* What we have here is a simple polynomial hash.
     * x0 * a^k-1 .. xk * a^k-k +1
     * It is reduced modulo a prime (and not 2^32), so that two different
     * keys of k bytes collide for at most k multipliers: colliding keys
     * can't be prepared without knowing the multiplier.
     */
    while (*key) {
        hash_key *= self->constant;
        hash_key += (unsigned char) * key;
        hash_key %= OSHASH_PRIME;
        key++;
    }

    return ((unsigned int)hash_key);
}

/* Set new size for hash
 * Returns 0 on error (out of memory)
 */
int OSHash_setSize(OSHash *self, unsigned int new_size)
{
    unsigned int i = 0;

    /* We can't decrease the size */
    if (new_size <= self->rows) {
        return (1);
    }

    /* Get next prime */
    self->rows = os_getprime(new_size);
    if (self->rows == 0) {
        return (0);
    }

    /* If we fail, the hash should not be used anymore */
    self->table = (OSHashNode **) realloc(self->table, (self->rows + 1) * sizeof(OSHashNode *));
    if (!self->table) {
        return (0);
    }

    /* Zero our tables */
    for (i = 0; i <= self->rows; i++) {
        self->table[i] = NULL;
    }

    /* New seed */
    if (!_os_genseed(self)) {
        return (0);
    }

    return (1);
}


/** int OSHash_Update(OSHash *self, char *key, void *data)
 * Returns 0 on error (not found).
 * Returns 1 on successduplicated key (not added)
 * Key must not be NULL.
 */
int OSHash_Update(OSHash *self, const char *key, void *data)
{
    unsigned int hash_key;
    unsigned int index;
    OSHashNode *curr_node;

    /* Generate hash of the message */
    hash_key = _os_genhash(self, key);

    /* Get array index */
    index = hash_key % self->rows;

    /* Check for duplicated entries in the index */
    curr_node = self->table[index];
    while (curr_node) {
        /* Checking for duplicated key -- not adding */
        if (strcmp(curr_node->key, key) == 0) {
            curr_node->data = data;
            return (1);
        }
        curr_node = curr_node->next;
    }
    return (0);
}

/** int OSHash_Add(OSHash *self, char *key, void *data)
 * Returns 0 on error.
 * Returns 1 on duplicated key (not added)
 * Returns 2 on success
 * Key must not be NULL.
 */
int OSHash_Add(OSHash *self, const char *key, void *data)
{
    unsigned int hash_key;
    unsigned int index;
    OSHashNode *curr_node;
    OSHashNode *new_node;

    /* Generate hash of the message */
    hash_key = _os_genhash(self, key);

    /* Get array index */
    index = hash_key % self->rows;

    /* Check for duplicated entries in the index */
    curr_node = self->table[index];
    while (curr_node) {
        /* Checking for duplicated key -- not adding */
        if (strcmp(curr_node->key, key) == 0) {
            /* Not adding */
            return (1);
        }
        curr_node = curr_node->next;
    }

    /* Create new node */
    new_node = (OSHashNode *) calloc(1, sizeof(OSHashNode));
    if (!new_node) {
        return (0);
    }
    new_node->next = NULL;
    new_node->data = data;
    new_node->key = strdup(key);
    if ( new_node->key == NULL ) {
        free(new_node);
        debug1("hash_op: DEBUG: strdup() failed!");
        return (0);
    }

    /* Add to table */
    if (!self->table[index]) {
        self->table[index] = new_node;
    }
    /* If there is duplicated, add to the beginning */
    else {
        new_node->next = self->table[index];
        self->table[index] = new_node;
    }

    return (2);
}

/** void *OSHash_Get(OSHash *self, char *key)
 * Returns NULL on error (key not found).
 * Returns the key otherwise.
 * Key must not be NULL.
 */
void *OSHash_Get(const OSHash *self, const char *key)
{
    unsigned int hash_key;
    unsigned int index;
    const OSHashNode *curr_node;

    /* Generate hash of the message */
    hash_key = _os_genhash(self, key);

    /* Get array index */
    index = hash_key % self->rows;

    /* Get entry */
    curr_node = self->table[index];
    while (curr_node != NULL) {


        /* We may have collisions, so double check with strcmp */
        if (curr_node->key != NULL && strcmp(curr_node->key, key) == 0) {

            return (curr_node->data);
        }

        curr_node = curr_node->next;
    }

    return (NULL);
}

/* Return a pointer to a hash node if found, that hash node is removed from the table */
void *OSHash_Delete(OSHash *self, const char *key)
{
    OSHashNode *curr_node;
    OSHashNode *prev_node = 0;
    unsigned int hash_key;
    unsigned int index;
    void *data;

    /* Generate hash of the message */
    hash_key = _os_genhash(self, key);

    /* Get array index */
    index = hash_key % self->rows;

    curr_node = self->table[index];
    while ( curr_node != NULL ) {
        if (strcmp(curr_node->key, key) == 0) {
            if ( prev_node == NULL ) {
                self->table[index] = curr_node->next;
            } else {
                prev_node->next = curr_node->next;
            }
            free(curr_node->key);
            data = curr_node->data;
            free(curr_node);
            return data;
        }
        prev_node = curr_node;
        curr_node = curr_node->next;
    }

    return NULL;
}
