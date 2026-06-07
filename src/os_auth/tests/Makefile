# authd unit tests (standalone, not part of default `make` in src/)

CC ?= gcc
CFLAGS = -g -Wall -I../../ -I../../headers -I../../external/compat \
	-DARGV0=\"auth_conn_drop_test\"

AUTH_CONN_DROP_TEST_OBJS = auth_conn_drop_test.o \
	../auth_conn_drop.o

auth_conn_drop_test: $(AUTH_CONN_DROP_TEST_OBJS)
	$(CC) $(CFLAGS) -o $@ $(AUTH_CONN_DROP_TEST_OBJS)

auth_conn_drop_test.o: auth_conn_drop_test.c
	$(CC) $(CFLAGS) -c $< -o $@

../auth_conn_drop.o: ../auth_conn_drop.c
	$(CC) $(CFLAGS) -c ../auth_conn_drop.c -o ../auth_conn_drop.o

clean:
	rm -f auth_conn_drop_test *.o

.PHONY: clean
