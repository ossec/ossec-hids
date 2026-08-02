# Unified analysisd / pipeline regression suite.
# Run from src/ after a normal server build (live objects + libs):
#
#   make TARGET=server -j$(nproc)
#   make -f tests/regressions/Makefile
#   make -f tests/regressions/Makefile check
#
# Or from src/:
#   make regression

CC ?= cc
CFLAGS += -I./ -I./headers -I./analysisd -Wall -Wextra
CFLAGS += -DARGV0=\"ossec-analysisd\"

EVENTINFO_OBJS = analysisd/eventinfo-live.o analysisd/eventinfo_list-live.o
CORRELATION_OBJS = $(EVENTINFO_OBJS) analysisd/correlation_shard-live.o
BASIC_LIBS = -Wl,--start-group shared.a os_regex.a -Wl,--end-group -lpcre2-8 -lm -lpthread

REGRESSION_BINS = \
	issue_1079_last_events_uaf \
	issue_correlation_agent_shard \
	issue_1748_sid_list_crash \
	issue_1274_auth_ipv6_key

.PHONY: all check clean

all: $(REGRESSION_BINS)

check: all
	@failed=0; \
	for bin in $(REGRESSION_BINS); do \
		echo "=== $$bin ==="; \
		./$$bin || failed=1; \
	done; \
	if [ $$failed -ne 0 ]; then \
		echo "FAIL: one or more regression tests failed"; \
		exit 1; \
	fi; \
	echo "PASS: all analysisd regressions"

issue_1079_last_events_uaf: tests/regressions/issue_1079_last_events_uaf.c $(EVENTINFO_OBJS) shared.a
	$(CC) $(CFLAGS) -o $@ tests/regressions/issue_1079_last_events_uaf.c $(EVENTINFO_OBJS) $(BASIC_LIBS)

issue_correlation_agent_shard: tests/regressions/issue_correlation_agent_shard.c $(CORRELATION_OBJS) shared.a
	$(CC) $(CFLAGS) -DARGV0=\"issue_correlation_agent_shard\" \
		-o $@ tests/regressions/issue_correlation_agent_shard.c $(CORRELATION_OBJS) $(BASIC_LIBS)

issue_1748_sid_list_crash: tests/regressions/issue_1748_sid_list_crash.c $(EVENTINFO_OBJS) shared.a
	$(CC) $(CFLAGS) -o $@ tests/regressions/issue_1748_sid_list_crash.c $(EVENTINFO_OBJS) $(BASIC_LIBS)

issue_1274_auth_ipv6_key: tests/regressions/issue_1274_auth_ipv6_key.c addagent/validate.o shared.a os_crypto.a
	$(CC) $(CFLAGS) -o $@ tests/regressions/issue_1274_auth_ipv6_key.c addagent/validate.o \
		-Wl,--start-group shared.a os_regex.a os_crypto.a os_net.a os_xml.a os_zlib.a libcJSON.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto -lz

addagent/validate.o: addagent/validate.c
	$(CC) $(CFLAGS) -c addagent/validate.c -o $@

clean:
	rm -f $(REGRESSION_BINS)
