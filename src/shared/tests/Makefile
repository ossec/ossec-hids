# Makefile for misc shared-library unit tests.
# Prefer linking against built libs from src/:
#   cd src && make shared.a
#   make -C shared/tests check

CC ?= cc
TOP = ../..
CFLAGS_COMMON = -g -Wall -I$(TOP)/headers -I$(TOP) -I$(TOP)/analysisd

# Headless tests run by `check`. Interactive helpers stay under `legacy_helpers`.
AUTO_TEST_BINS = thread_pool_test queue_op_test string_test fim_sum_test ar_expect_test fim_maint_test win_acl_test
LEGACY_HELPER_BINS = prime_test hash_test merge_test ip_test

.PHONY: maketest check clean legacy_helpers

thread_pool_test: thread_pool_test.c
	$(CC) -pthread $(CFLAGS_COMMON) -DARGV0=\"thread_pool_test\" \
		-DTHREAD_POOL_TEST_HOOK -o $@ thread_pool_test.c \
		../thread_pool.c ../pthreads_op.c ../mem_op.c ../debug_op.c \
		../string_op.c ../file_op.c

queue_op_test: queue_op_test.c $(TOP)/shared.a
	$(CC) -pthread $(CFLAGS_COMMON) -DARGV0=\"queue_op_test\" -o $@ \
		queue_op_test.c $(TOP)/shared.a -lpthread

string_test: string_test.c
	$(CC) $(CFLAGS_COMMON) -DARGV0=\"string_test\" -o $@ string_test.c ../string_op.c

fim_sum_test: fim_sum_test.c ../fim_sum_op.c ../../headers/fim_sum_op.h
	$(CC) $(CFLAGS_COMMON) -DARGV0=\"fim_sum_test\" -o $@ fim_sum_test.c ../fim_sum_op.c

win_acl_test: win_acl_test.c ../../headers/win_acl_op.h $(TOP)/shared.a
	$(CC) $(CFLAGS_COMMON) -DARGV0=\"win_acl_test\" -o $@ \
		win_acl_test.c \
		-Wl,--start-group $(TOP)/shared.a $(TOP)/os_crypto.a -Wl,--end-group

ar_expect_test: ar_expect_test.c ../ar_expect.c ../../headers/ar.h
	$(CC) $(CFLAGS_COMMON) -DARGV0=\"ar_expect_test\" -o $@ \
		ar_expect_test.c ../ar_expect.c

fim_maint_test: fim_maint_test.c $(TOP)/shared.a
	$(CC) -pthread $(CFLAGS_COMMON) -DARGV0=\"fim_maint_test\" -o $@ \
		fim_maint_test.c \
		-Wl,--start-group $(TOP)/shared.a $(TOP)/os_regex.a $(TOP)/os_net.a \
		$(TOP)/os_xml.a $(TOP)/os_zlib.a $(TOP)/libcJSON.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lz

# Interactive / argv-driven helpers (not part of automated check).
legacy_helpers:
	$(CC) -g -I$(TOP)/headers -I$(TOP) -DARGV0=\"prime_test\" -o prime_test \
		prime_test.c ../math_op.c
	$(CC) -g -I$(TOP)/headers -I$(TOP) -DARGV0=\"hash_test\" -o hash_test \
		hash_test.c ../hash_op.c ../math_op.c ../debug_op.c ../mem_op.c
	$(CC) -g -I$(TOP)/headers -I$(TOP) -DARGV0=\"merge_test\" -o merge_test \
		merge_test.c ../file_op.c ../debug_op.c ../string_op.c ../mem_op.c
	$(CC) -g -I$(TOP)/headers -I$(TOP) -DARGV0=\"ip_test\" -o ip_test \
		ip_test.c ../validate_op.c ../debug_op.c ../regex_op.c ../mem_op.c \
		../string_op.c

maketest: $(AUTO_TEST_BINS)

check: $(AUTO_TEST_BINS)
	@failed=0; \
	for bin in $(AUTO_TEST_BINS); do \
		echo "=== $$bin ==="; \
		./$$bin || failed=1; \
	done; \
	if [ $$failed -ne 0 ]; then \
		echo "FAIL: shared unit tests"; \
		exit 1; \
	fi; \
	echo "PASS: shared unit tests"

clean:
	-rm -f $(AUTO_TEST_BINS) $(LEGACY_HELPER_BINS) *.core
