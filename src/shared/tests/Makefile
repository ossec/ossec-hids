# Makefile for misc tests

THREAD_POOL_TEST_OBJS = thread_pool_test.c ../thread_pool.c ../pthreads_op.c \
	../mem_op.c ../debug_op.c ../string_op.c ../file_op.c

thread_pool_test: $(THREAD_POOL_TEST_OBJS)
	$(CC) -pthread -g -o $@ $(THREAD_POOL_TEST_OBJS) -I../../headers/ -I../../ \
		-DARGV0=\"thread_pool_test\" -DTHREAD_POOL_TEST_HOOK -Wall

maketest: thread_pool_test
		$(CC) -g -o string_test string_test.c ../string_op.c -I../ -I../../ -I../../headers/ -I../headers/ -Wall
		$(CC) -g -o prime_test prime_test.c ../math_op.c -I../ -I../../ -I../../headers/ -I../headers/ -Wall
		$(CC) -g -o hash_test hash_test.c ../hash_op.c ../math_op.c -I../ -I../../ -I../../headers/ -I../headers/ -Wall
		$(CC) -g -o merge_test merge_test.c  ../file_op.c ../debug_op.c -I../ -I../../ -I../../headers/ -I../headers/ -Wall
		$(CC) -DARGV0=\"ip_test\" -g -o ip_test ip_test.c ../validate_op.c ../debug_op.c ../regex_op.c -I../ -I../../ -I../../headers/ -I../headers/ -Wall

clean:
		-rm string_test prime_test hash_test merge_test ip_test thread_pool_test *.core
