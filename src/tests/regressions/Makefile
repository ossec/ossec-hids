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
CFLAGS += -I./ -I./headers -I./analysisd -I./external/compat -Wall -Wextra
CFLAGS += -DARGV0=\"ossec-analysisd\"

EVENTINFO_OBJS = analysisd/eventinfo-live.o analysisd/eventinfo_list-live.o
CORRELATION_OBJS = $(EVENTINFO_OBJS) analysisd/correlation_shard-live.o
BASIC_LIBS = -Wl,--start-group shared.a os_regex.a -Wl,--end-group -lpcre2-8 -lm -lpthread

REGRESSION_BINS = \
	issue_1079_last_events_uaf \
	issue_correlation_agent_shard \
	issue_1748_sid_list_crash \
	issue_group_list_uaf \
	issue_prev_matched_race \
	issue_1274_auth_ipv6_key \
	issue_2065_sender_counter \
	issue_1611_local_ip_bind \
	issue_1668_agent_hostname \
	issue_1668_ossecalert_hostname \
	unmerge_path_traversal \
	jsonout_default \
	issue_1814_control_chars \
	issue_cleanevent_date_oob \
	issue_1953_xml_recursion \
	issue_2100_authd_ssl \
	getalert_empty_filename \
	multiline_underflow \
	win_network_path \
	checksum_short_message \
	issue_empty_ciphertext \
	issue_win_execd_cmd_injection \
	issue_logs_symlink_nofollow \
	issue_ar_location_injection \
	issue_ads_stream_overflow \
	issue_win_parent_folder \
	issue_syscheck_prefix_sum_size \
	issue_bind_unix_chmod_race

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

issue_group_list_uaf: tests/regressions/issue_group_list_uaf.c $(EVENTINFO_OBJS) shared.a
	$(CC) $(CFLAGS) -o $@ tests/regressions/issue_group_list_uaf.c $(EVENTINFO_OBJS) $(BASIC_LIBS)

issue_prev_matched_race: tests/regressions/issue_prev_matched_race.c $(EVENTINFO_OBJS) shared.a
	$(CC) $(CFLAGS) -o $@ tests/regressions/issue_prev_matched_race.c $(EVENTINFO_OBJS) $(BASIC_LIBS)

issue_1274_auth_ipv6_key: tests/regressions/issue_1274_auth_ipv6_key.c addagent/validate.o shared.a os_crypto.a
	$(CC) $(CFLAGS) -o $@ tests/regressions/issue_1274_auth_ipv6_key.c addagent/validate.o \
		-Wl,--start-group shared.a os_regex.a os_crypto.a os_net.a os_xml.a os_zlib.a libcJSON.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto -lz

issue_2065_sender_counter: tests/regressions/issue_2065_sender_counter.c os_crypto.a shared.a
	$(CC) $(CFLAGS) -o $@ tests/regressions/issue_2065_sender_counter.c \
		-Wl,--start-group shared.a os_regex.a os_crypto.a os_net.a os_xml.a os_zlib.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto -lz

issue_1611_local_ip_bind: tests/regressions/issue_1611_local_ip_bind.c os_net.a shared.a
	$(CC) $(CFLAGS) -o $@ tests/regressions/issue_1611_local_ip_bind.c \
		-Wl,--start-group shared.a os_regex.a os_net.a os_xml.a os_zlib.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lz

issue_1668_agent_hostname: tests/regressions/issue_1668_agent_hostname.c \
		analysisd/cleanevent.c analysisd/eventinfo.c analysisd/eventinfo_list.c shared.a
	$(CC) $(CFLAGS) -I./analysisd -c analysisd/cleanevent.c -o analysisd/cleanevent-1668.o
	$(CC) $(CFLAGS) -I./analysisd -c analysisd/eventinfo.c -o analysisd/eventinfo-1668.o
	$(CC) $(CFLAGS) -I./analysisd -c analysisd/eventinfo_list.c -o analysisd/eventinfo_list-1668.o
	$(CC) $(CFLAGS) -I./analysisd -o $@ tests/regressions/issue_1668_agent_hostname.c \
		analysisd/cleanevent-1668.o analysisd/eventinfo-1668.o analysisd/eventinfo_list-1668.o \
		-Wl,--start-group shared.a os_regex.a os_net.a os_xml.a os_zlib.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lz

issue_1668_ossecalert_hostname: tests/regressions/issue_1668_ossecalert_hostname.c \
		analysisd/cleanevent.c analysisd/eventinfo.c analysisd/eventinfo_list.c \
		analysisd/decoders/plugins/ossecalert_decoder.c shared.a
	$(CC) $(CFLAGS) -I./analysisd -c analysisd/cleanevent.c -o analysisd/cleanevent-1668oa.o
	$(CC) $(CFLAGS) -I./analysisd -c analysisd/eventinfo.c -o analysisd/eventinfo-1668oa.o
	$(CC) $(CFLAGS) -I./analysisd -c analysisd/eventinfo_list.c -o analysisd/eventinfo_list-1668oa.o
	$(CC) $(CFLAGS) -I./analysisd -c analysisd/decoders/plugins/ossecalert_decoder.c \
		-o analysisd/decoders/plugins/ossecalert_decoder-1668oa.o
	$(CC) $(CFLAGS) -I./analysisd -o $@ tests/regressions/issue_1668_ossecalert_hostname.c \
		analysisd/cleanevent-1668oa.o analysisd/eventinfo-1668oa.o analysisd/eventinfo_list-1668oa.o \
		analysisd/decoders/plugins/ossecalert_decoder-1668oa.o \
		-Wl,--start-group shared.a os_regex.a os_net.a os_xml.a os_zlib.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lz

unmerge_path_traversal: tests/regressions/unmerge_path_traversal.c shared.a
	$(CC) $(CFLAGS) -o $@ tests/regressions/unmerge_path_traversal.c \
		-Wl,--start-group shared.a os_regex.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread

# GlobalConf lives in analysisd/config.c (defines _Config Config).
# Link config.a from a current server build; do not also compile
# config/global-config.c or Read_Global is defined twice.
jsonout_default: tests/regressions/jsonout_default.c analysisd/config.c config.a shared.a
	$(CC) $(CFLAGS) -I./analysisd -o $@ tests/regressions/jsonout_default.c analysisd/config.c \
		-Wl,--start-group config.a shared.a os_regex.a os_net.a os_xml.a os_zlib.a libcJSON.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lz

issue_1814_control_chars: tests/regressions/issue_1814_control_chars.c analysisd/cleanevent.c shared.a
	$(CC) $(CFLAGS) -I./analysisd -DTESTRULE -c analysisd/cleanevent.c -o analysisd/cleanevent-1814.o
	$(CC) $(CFLAGS) -I./analysisd -o $@ tests/regressions/issue_1814_control_chars.c \
		analysisd/cleanevent-1814.o \
		-Wl,--start-group shared.a os_regex.a os_net.a os_xml.a os_zlib.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lz

issue_cleanevent_date_oob: tests/regressions/issue_cleanevent_date_oob.c analysisd/cleanevent.c \
		analysisd/eventinfo.c analysisd/eventinfo_list.c shared.a
	$(CC) $(CFLAGS) -I./analysisd -c analysisd/cleanevent.c -o analysisd/cleanevent-8r0.o
	$(CC) $(CFLAGS) -I./analysisd -c analysisd/eventinfo.c -o analysisd/eventinfo-8r0.o
	$(CC) $(CFLAGS) -I./analysisd -c analysisd/eventinfo_list.c -o analysisd/eventinfo_list-8r0.o
	$(CC) $(CFLAGS) -I./analysisd -o $@ tests/regressions/issue_cleanevent_date_oob.c \
		analysisd/cleanevent-8r0.o analysisd/eventinfo-8r0.o analysisd/eventinfo_list-8r0.o \
		-Wl,--start-group shared.a os_regex.a os_net.a os_xml.a os_zlib.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lz

issue_1953_xml_recursion: tests/regressions/issue_1953_xml_recursion.c os_xml.a shared.a
	$(CC) $(CFLAGS) -I./os_xml -o $@ tests/regressions/issue_1953_xml_recursion.c \
		-Wl,--start-group os_xml.a shared.a os_regex.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread

issue_2100_authd_ssl: tests/regressions/issue_2100_authd_ssl.c os_auth/ssl.c shared.a
	$(CC) $(CFLAGS) -DLIBOPENSSL_ENABLED -c os_auth/ssl.c -o os_auth/ssl-2100.o
	$(CC) $(CFLAGS) -DLIBOPENSSL_ENABLED -o $@ tests/regressions/issue_2100_authd_ssl.c os_auth/ssl-2100.o \
		-Wl,--start-group shared.a os_regex.a os_net.a os_xml.a os_zlib.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto -lz

getalert_empty_filename: tests/regressions/getalert_empty_filename.c shared.a
	$(CC) $(CFLAGS) -o $@ tests/regressions/getalert_empty_filename.c \
		-Wl,--start-group shared.a os_regex.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread

checksum_short_message: tests/regressions/checksum_short_message.c os_crypto/shared/msgs.c
	$(CC) $(CFLAGS) -c os_crypto/shared/msgs.c -o os_crypto/shared/msgs-checksum.o
	$(CC) $(CFLAGS) -Wno-implicit-fallthrough -I./os_crypto/blowfish -c os_crypto/blowfish/bf_op.c -o os_crypto/blowfish/bf_op-checksum.o
	$(CC) $(CFLAGS) -Wno-implicit-fallthrough -I./os_crypto/blowfish -c os_crypto/blowfish/bf_enc.c -o os_crypto/blowfish/bf_enc-checksum.o
	$(CC) $(CFLAGS) -Wno-implicit-fallthrough -I./os_crypto/blowfish -c os_crypto/blowfish/bf_skey.c -o os_crypto/blowfish/bf_skey-checksum.o
	$(CC) $(CFLAGS) -I./os_crypto/md5 -c os_crypto/md5/md5.c -o os_crypto/md5/md5-checksum.o
	$(CC) $(CFLAGS) -I./os_crypto/md5 -c os_crypto/md5/md5_op.c -o os_crypto/md5/md5_op-checksum.o
	$(CC) $(CFLAGS) -o $@ tests/regressions/checksum_short_message.c \
		os_crypto/shared/msgs-checksum.o \
		os_crypto/blowfish/bf_op-checksum.o \
		os_crypto/blowfish/bf_enc-checksum.o \
		os_crypto/blowfish/bf_skey-checksum.o \
		os_crypto/md5/md5-checksum.o \
		os_crypto/md5/md5_op-checksum.o \
		-lpthread

# Same crypto objects as checksum_short_message (empty/oversized body → 1405).
issue_empty_ciphertext: tests/regressions/issue_empty_ciphertext.c os_crypto/shared/msgs.c
	$(CC) $(CFLAGS) -c os_crypto/shared/msgs.c -o os_crypto/shared/msgs-empty.o
	$(CC) $(CFLAGS) -Wno-implicit-fallthrough -I./os_crypto/blowfish -c os_crypto/blowfish/bf_op.c -o os_crypto/blowfish/bf_op-empty.o
	$(CC) $(CFLAGS) -Wno-implicit-fallthrough -I./os_crypto/blowfish -c os_crypto/blowfish/bf_enc.c -o os_crypto/blowfish/bf_enc-empty.o
	$(CC) $(CFLAGS) -Wno-implicit-fallthrough -I./os_crypto/blowfish -c os_crypto/blowfish/bf_skey.c -o os_crypto/blowfish/bf_skey-empty.o
	$(CC) $(CFLAGS) -I./os_crypto/md5 -c os_crypto/md5/md5.c -o os_crypto/md5/md5-empty.o
	$(CC) $(CFLAGS) -I./os_crypto/md5 -c os_crypto/md5/md5_op.c -o os_crypto/md5/md5_op-empty.o
	$(CC) $(CFLAGS) -o $@ tests/regressions/issue_empty_ciphertext.c \
		os_crypto/shared/msgs-empty.o \
		os_crypto/blowfish/bf_op-empty.o \
		os_crypto/blowfish/bf_enc-empty.o \
		os_crypto/blowfish/bf_skey-empty.o \
		os_crypto/md5/md5-empty.o \
		os_crypto/md5/md5_op-empty.o \
		-lpthread

win_network_path: tests/regressions/win_network_path.c shared/win_path.c
	$(CC) $(CFLAGS) -o $@ tests/regressions/win_network_path.c shared/win_path.c

issue_win_execd_cmd_injection: tests/regressions/issue_win_execd_cmd_injection.c shared.a
	$(CC) $(CFLAGS) -o $@ tests/regressions/issue_win_execd_cmd_injection.c $(BASIC_LIBS)

issue_logs_symlink_nofollow: tests/regressions/issue_logs_symlink_nofollow.c shared.a
	$(CC) $(CFLAGS) -o $@ tests/regressions/issue_logs_symlink_nofollow.c \
		-Wl,--start-group shared.a os_regex.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread

issue_ar_location_injection: tests/regressions/issue_ar_location_injection.c shared.a
	$(CC) $(CFLAGS) -o $@ tests/regressions/issue_ar_location_injection.c \
		-Wl,--start-group shared.a os_regex.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread

issue_ads_stream_overflow: tests/regressions/issue_ads_stream_overflow.c rootcheck/win-common.c
	$(CC) $(CFLAGS) -I./rootcheck -o $@ tests/regressions/issue_ads_stream_overflow.c \
		rootcheck/win-common.c

issue_win_parent_folder: tests/regressions/issue_win_parent_folder.c shared.a
	$(CC) $(CFLAGS) -o $@ tests/regressions/issue_win_parent_folder.c \
		-Wl,--start-group shared.a os_regex.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread

issue_syscheck_prefix_sum_size: tests/regressions/issue_syscheck_prefix_sum_size.c \
		analysisd/decoders/syscheck_db_entry.h headers/defs.h
	$(CC) $(CFLAGS) -I./analysisd -o $@ tests/regressions/issue_syscheck_prefix_sum_size.c

issue_bind_unix_chmod_race: tests/regressions/issue_bind_unix_chmod_race.c os_net.a shared.a
	$(CC) $(CFLAGS) -o $@ tests/regressions/issue_bind_unix_chmod_race.c \
		-Wl,--wrap=bind \
		-Wl,--start-group shared.a os_regex.a os_net.a os_xml.a os_zlib.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lz

# Build the reader without FORTIFY so a wrapped strncpy() stays a
# call to strncpy. With _FORTIFY_SOURCE the call becomes
# __strncpy_chk and the regression's length check never runs.
multiline_underflow: tests/regressions/multiline_underflow.c logcollector/read_multiline.c
	$(CC) $(CFLAGS) -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -fno-builtin-strncpy \
		-I./logcollector -c logcollector/read_multiline.c -o logcollector/read_multiline-underflow.o
	$(CC) $(CFLAGS) -I./logcollector -o $@ tests/regressions/multiline_underflow.c \
		logcollector/read_multiline-underflow.o

addagent/validate.o: addagent/validate.c
	$(CC) $(CFLAGS) -c addagent/validate.c -o $@

clean:
	rm -f $(REGRESSION_BINS) \
		analysisd/cleanevent-1668.o analysisd/eventinfo-1668.o \
		analysisd/eventinfo_list-1668.o \
		analysisd/cleanevent-1668oa.o analysisd/eventinfo-1668oa.o \
		analysisd/eventinfo_list-1668oa.o \
		analysisd/decoders/plugins/ossecalert_decoder-1668oa.o \
		analysisd/cleanevent-1814.o \
		analysisd/cleanevent-8r0.o analysisd/eventinfo-8r0.o \
		analysisd/eventinfo_list-8r0.o \
		os_auth/ssl-2100.o \
		logcollector/read_multiline-underflow.o \
		os_crypto/shared/msgs-checksum.o \
		os_crypto/blowfish/bf_op-checksum.o \
		os_crypto/blowfish/bf_enc-checksum.o \
		os_crypto/blowfish/bf_skey-checksum.o \
		os_crypto/md5/md5-checksum.o \
		os_crypto/md5/md5_op-checksum.o \
		os_crypto/shared/msgs-empty.o \
		os_crypto/blowfish/bf_op-empty.o \
		os_crypto/blowfish/bf_enc-empty.o \
		os_crypto/blowfish/bf_skey-empty.o \
		os_crypto/md5/md5-empty.o \
		os_crypto/md5/md5_op-empty.o
