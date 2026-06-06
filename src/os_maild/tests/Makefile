# maild list unit tests (standalone, not part of default `make` in src/)

CC ?= gcc
CFLAGS = -g -Wall -I../../ -I../../headers -I../../external/compat \
	-DARGV0=\"mail_list_requeue_test\"

MAIL_LIST_TEST_OBJS = mail_list_requeue_test.o \
	../mail_list.o \
	../../shared/pthreads_op.o \
	../../shared/debug_op.o \
	../../shared/file_op.o \
	../../shared/string_op.o

SMS_QUEUE_TEST_OBJS = sms_queue_test.o \
	../sms_queue.o \
	../mail_list.o \
	../../shared/pthreads_op.o \
	../../shared/debug_op.o \
	../../shared/file_op.o \
	../../shared/string_op.o \
	../../shared/mem_op.o

mail_list_requeue_test: $(MAIL_LIST_TEST_OBJS)
	$(CC) $(CFLAGS) -o $@ $(MAIL_LIST_TEST_OBJS) -lpthread

sms_queue_test: $(SMS_QUEUE_TEST_OBJS)
	$(CC) $(CFLAGS) -o $@ $(SMS_QUEUE_TEST_OBJS) -lpthread

mail_list_requeue_test.o: mail_list_requeue_test.c
	$(CC) $(CFLAGS) -c $< -o $@

sms_queue_test.o: sms_queue_test.c
	$(CC) $(CFLAGS) -c $< -o $@

../mail_list.o: ../mail_list.c
	$(MAKE) -C ../.. os_maild/mail_list.o 2>/dev/null || \
	$(CC) $(CFLAGS) -c ../mail_list.c -o ../mail_list.o

../sms_queue.o: ../sms_queue.c
	$(MAKE) -C ../.. os_maild/sms_queue.o 2>/dev/null || \
	$(CC) $(CFLAGS) -c ../sms_queue.c -o ../sms_queue.o

clean:
	rm -f mail_list_requeue_test sms_queue_test *.o

.PHONY: clean
