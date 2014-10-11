/* Copyright (C) 2014 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <check.h>
#include <stdlib.h>

#include "../headers/hash_op.h"
#include "./diceware.wordlist.h"
#include <sys/time.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include "uthash.h"

/* Return 1 if the difference is negative, otherwise 0.  */
int timeval_subtract(struct timeval *result, struct timeval *t2, struct timeval *t1)
{
    long int diff = (t2->tv_usec + 1000000 * t2->tv_sec) - (t1->tv_usec + 1000000 * t1->tv_sec);
    result->tv_sec = diff / 1000000;
    result->tv_usec = diff % 1000000;

    return (diff<0);
}

Suite *test_suite(void);

START_TEST(test_oshash_add)
{
    struct timeval tvBegin, tvEnd, tvDiff;
    gettimeofday(&tvBegin, NULL);
    int i;
    int rc; 
    char * value; 
    OSHash *h = OSHash_Create();

    for(i=0; diceware[i][0] != NULL ; i++) {
        rc = OSHash_Add(h, (const char *)diceware[i][0], (void *)diceware[i][1]);
        //ck_assert_int_eq(rc, 2);

        value = OSHash_Get(h, diceware[i][0]);
        //ck_assert_str_eq(diceware[i][1], value);
    }

    OSHash_Free(h);
    gettimeofday(&tvEnd, NULL);
    timeval_subtract(&tvDiff, &tvEnd, &tvBegin);
    printf("test_oshash_add: %ld.%06ld\n", tvDiff.tv_sec, tvDiff.tv_usec);

}
END_TEST

START_TEST(test_oshash_add_twice)
{
    struct timeval tvBegin, tvEnd, tvDiff;
    gettimeofday(&tvBegin, NULL);
    int i;
    int rc; 
    char * value; 
    OSHash *h = OSHash_Create();

    for(i=0; diceware[i][0] != NULL ; i++) {
        rc = OSHash_Add(h, (const char *)diceware[i][0], (void *)diceware[i][1]);
        //ck_assert_int_eq(rc, 2);
    }
    for(i=0; diceware[i][0] != NULL ; i++) {
        rc = OSHash_Add(h, (const char *)diceware[i][0], (void *)diceware[i][1]);
        //ck_assert_int_eq(rc, 1);
    }

    OSHash_Free(h);
    gettimeofday(&tvEnd, NULL);
    timeval_subtract(&tvDiff, &tvEnd, &tvBegin);
    printf("test_oshash_twice: %ld.%06ld\n", tvDiff.tv_sec, tvDiff.tv_usec);
}
END_TEST

START_TEST(test_oshash_delete)
{
    struct timeval tvBegin, tvEnd, tvDiff;
    gettimeofday(&tvBegin, NULL);
    int i;
    int rc; 
    char * value; 
    OSHash *h = OSHash_Create();

    value = OSHash_Delete(h, "abject");
    //ck_assert_msg(value == NULL, "nothign toremoved should always be NULL");

    for(i=0; diceware[i][0] != NULL ; i++) {
        rc = OSHash_Add(h, (const char *)diceware[i][0], (void *)diceware[i][1]);
        //ck_assert_int_eq(rc, 2);
    }

    value = OSHash_Delete(h, "abject");
    //ck_assert_str_eq(value,"11152");

    value = OSHash_Delete(h, "abject");
    //ck_assert_msg(value == NULL, "already removed should always be NULL");

    OSHash_Free(h);
    gettimeofday(&tvEnd, NULL);
    timeval_subtract(&tvDiff, &tvEnd, &tvBegin);
    printf("test_oshash_delete: %ld.%06ld\n", tvDiff.tv_sec, tvDiff.tv_usec);
}
END_TEST

struct ut_kv {
    const char *key;
    const char *value;
    UT_hash_handle hh;         /* makes this structure hashable */
};

START_TEST(test_uthash_add)
{
    struct timeval tvBegin, tvEnd, tvDiff;
    gettimeofday(&tvBegin, NULL);

    int i;
    struct ut_kv *s, *tmp, *h;

    for(i=0; diceware[i][0] != NULL ; i++) {
        s = (struct ut_kv*)malloc(sizeof(struct ut_kv));
        s->key = diceware[i][0]; 
        s->value = diceware[i][1];
        HASH_ADD_KEYPTR(hh, h, s->key, strlen(s->key), s);

        HASH_FIND_STR(h, diceware[i][0], tmp);
        //ck_assert_str_eq(diceware[i][1], tmp->value);
    }
    HASH_ITER(hh, h, s, tmp) {
        HASH_DEL(h, s);
        free(s);
    }

    gettimeofday(&tvEnd, NULL);
    timeval_subtract(&tvDiff, &tvEnd, &tvBegin);
    printf("test_uthash_add: %ld.%06ld\n", tvDiff.tv_sec, tvDiff.tv_usec);

}
END_TEST

START_TEST(test_uthash_add_twice)
{
    struct timeval tvBegin, tvEnd, tvDiff;
    gettimeofday(&tvBegin, NULL);

    int i;
    struct ut_kv *s, *tmp, *h;
    

    for(i=0; diceware[i][0] != NULL ; i++) {
        s = (struct ut_kv*)malloc(sizeof(struct ut_kv));
        s->key = diceware[i][0]; 
        s->value = diceware[i][1];
        HASH_ADD_KEYPTR(hh, h, s->key, strlen(s->key), s);

        HASH_FIND_STR(h, diceware[i][0], tmp);
        if(tmp == NULL) {
            s = (struct ut_kv*)malloc(sizeof(struct ut_kv));
            s->key = diceware[i][0]; 
            s->value = diceware[i][1];
            HASH_ADD_KEYPTR(hh, h, s->key, strlen(s->key), s);
        }
    }
    HASH_ITER(hh, h, s, tmp) {
        HASH_DEL(h, s);
        free(s);
    }

    gettimeofday(&tvEnd, NULL);
    timeval_subtract(&tvDiff, &tvEnd, &tvBegin);
    printf("test_uthash_add_twice: %ld.%06ld\n", tvDiff.tv_sec, tvDiff.tv_usec);

}
END_TEST

START_TEST(test_uthash_delete)
{
    struct timeval tvBegin, tvEnd, tvDiff;
    gettimeofday(&tvBegin, NULL);

    int i;
    struct ut_kv *s, *tmp, *h;
    

    for(i=0; diceware[i][0] != NULL ; i++) {
        s = (struct ut_kv*)malloc(sizeof(struct ut_kv));
        s->key = diceware[i][0]; 
        s->value = diceware[i][1];
        HASH_ADD_KEYPTR(hh, h, s->key, strlen(s->key), s);

        HASH_FIND_STR(h, diceware[i][0], tmp);
        if(tmp == NULL) {
            s = (struct ut_kv*)malloc(sizeof(struct ut_kv));
            s->key = diceware[i][0]; 
            s->value = diceware[i][1];
            HASH_ADD_KEYPTR(hh, h, s->key, strlen(s->key), s);
        }
    }
    HASH_FIND_STR(h, "abject", tmp);
    if(tmp != NULL) {
        HASH_DEL(h, tmp);
    }
    HASH_FIND_STR(h, "abject", tmp);
    if(tmp != NULL) {
        HASH_DEL(h, tmp);
    }
    HASH_ITER(hh, h, s, tmp) {
        HASH_DEL(h, s);
        free(s);
    }
    
    gettimeofday(&tvEnd, NULL);
    timeval_subtract(&tvDiff, &tvEnd, &tvBegin);
    printf("test_uthash_delete: %ld.%06ld\n", tvDiff.tv_sec, tvDiff.tv_usec);

}
END_TEST
Suite *test_suite(void)
{
    Suite *s = suite_create("shared_oshash");

    TCase *tc_oshash = tcase_create("oshash");
    tcase_add_test(tc_oshash, test_oshash_add);
    tcase_add_test(tc_oshash, test_oshash_add_twice);
    tcase_add_test(tc_oshash, test_oshash_delete);

    TCase *tc_uthash = tcase_create("uthash");
    tcase_add_test(tc_uthash, test_uthash_add);
    tcase_add_test(tc_uthash, test_uthash_add_twice);
    tcase_add_test(tc_uthash, test_uthash_delete);

    suite_add_tcase(s, tc_oshash);
    suite_add_tcase(s, tc_uthash);

    return (s);
}

int main(void)
{
    Suite *s = test_suite();
    SRunner *sr = srunner_create(s);
    srunner_run_all(sr, CK_NORMAL);
    int number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return ((number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE);
}
