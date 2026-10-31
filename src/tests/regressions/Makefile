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
# -lcrypto: OSHash_Create pulls randombytes via shared.a (ANT-2026-3WKK50NE).
BASIC_LIBS = -Wl,--start-group shared.a os_regex.a -Wl,--end-group -lpcre2-8 -lm -lpthread -lssl -lcrypto

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
	issue_bind_unix_chmod_race \
	issue_read_dir_path_overflow \
	issue_ossecalert_field_injection \
	issue_rootcheck_json_empty_name \
	issue_rootcheck_json_match_overflow \
	issue_hostname_path_traversal \
	issue_str_cut_overflow \
	issue_strtok_race \
	issue_dnxhhf88_localfile_double_free \
	issue_m5jt0jcl_authd_key_rng \
	issue_mon246f3_execd_ar_overflow \
	issue_ud31vlyl_audit_oob \
	issue_fb1hyskp_pagerduty_alertlog \
	issue_ant2026_ar_scripts \
	issue_3vn001l2_prefilter_retire \
	issue_c186ep5n_nodiff_size \
	issue_96vsxf8b_diff_store_symlink \
	issue_s3eu4a19_crawler_dns \
	issue_ktgcyz58_getalert_headers \
	issue_35jw8ghu_log_rollover \
	issue_rnce3so7_syslog_long_line \
	issue_h2jmyhxz_maild_subject_underflow \
	issue_3wkk50ne_oshash_collisions \
	issue_8sti0q1e_syscheck_linear_miss \
	issue_6wl10qqz_dir_depth \
	issue_2d3xma3w_decoder_field_leak \
	issue_tzmhdq9m_decoder_info_race

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
		-lpcre2-8 -lm -lpthread -lz -lssl -lcrypto

issue_1668_agent_hostname: tests/regressions/issue_1668_agent_hostname.c \
		analysisd/cleanevent.c analysisd/eventinfo.c analysisd/eventinfo_list.c \
		analysisd/accumulator.c shared.a
	$(CC) $(CFLAGS) -I./analysisd -c analysisd/cleanevent.c -o analysisd/cleanevent-1668.o
	$(CC) $(CFLAGS) -I./analysisd -c analysisd/eventinfo.c -o analysisd/eventinfo-1668.o
	$(CC) $(CFLAGS) -I./analysisd -c analysisd/eventinfo_list.c -o analysisd/eventinfo_list-1668.o
	$(CC) $(CFLAGS) -I./analysisd -c analysisd/accumulator.c -o analysisd/accumulator-1668.o
	$(CC) $(CFLAGS) -I./analysisd -o $@ tests/regressions/issue_1668_agent_hostname.c \
		analysisd/cleanevent-1668.o analysisd/eventinfo-1668.o analysisd/eventinfo_list-1668.o \
		analysisd/accumulator-1668.o \
		-Wl,--start-group shared.a os_regex.a os_net.a os_xml.a os_zlib.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lz -lssl -lcrypto

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
		-lpcre2-8 -lm -lpthread -lz -lssl -lcrypto

unmerge_path_traversal: tests/regressions/unmerge_path_traversal.c shared.a
	$(CC) $(CFLAGS) -o $@ tests/regressions/unmerge_path_traversal.c \
		-Wl,--start-group shared.a os_regex.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto

# GlobalConf lives in analysisd/config.c (defines _Config Config).
# Link config.a from a current server build; do not also compile
# config/global-config.c or Read_Global is defined twice.
jsonout_default: tests/regressions/jsonout_default.c analysisd/config.c config.a shared.a
	$(CC) $(CFLAGS) -I./analysisd -o $@ tests/regressions/jsonout_default.c analysisd/config.c \
		-Wl,--start-group config.a shared.a os_regex.a os_net.a os_xml.a os_zlib.a libcJSON.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lz -lssl -lcrypto

issue_1814_control_chars: tests/regressions/issue_1814_control_chars.c analysisd/cleanevent.c shared.a
	$(CC) $(CFLAGS) -I./analysisd -DTESTRULE -c analysisd/cleanevent.c -o analysisd/cleanevent-1814.o
	$(CC) $(CFLAGS) -I./analysisd -o $@ tests/regressions/issue_1814_control_chars.c \
		analysisd/cleanevent-1814.o \
		-Wl,--start-group shared.a os_regex.a os_net.a os_xml.a os_zlib.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lz -lssl -lcrypto

issue_cleanevent_date_oob: tests/regressions/issue_cleanevent_date_oob.c analysisd/cleanevent.c \
		analysisd/eventinfo.c analysisd/eventinfo_list.c shared.a
	$(CC) $(CFLAGS) -I./analysisd -c analysisd/cleanevent.c -o analysisd/cleanevent-8r0.o
	$(CC) $(CFLAGS) -I./analysisd -c analysisd/eventinfo.c -o analysisd/eventinfo-8r0.o
	$(CC) $(CFLAGS) -I./analysisd -c analysisd/eventinfo_list.c -o analysisd/eventinfo_list-8r0.o
	$(CC) $(CFLAGS) -I./analysisd -o $@ tests/regressions/issue_cleanevent_date_oob.c \
		analysisd/cleanevent-8r0.o analysisd/eventinfo-8r0.o analysisd/eventinfo_list-8r0.o \
		-Wl,--start-group shared.a os_regex.a os_net.a os_xml.a os_zlib.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lz -lssl -lcrypto

issue_1953_xml_recursion: tests/regressions/issue_1953_xml_recursion.c os_xml.a shared.a
	$(CC) $(CFLAGS) -I./os_xml -o $@ tests/regressions/issue_1953_xml_recursion.c \
		-Wl,--start-group os_xml.a shared.a os_regex.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto

issue_2100_authd_ssl: tests/regressions/issue_2100_authd_ssl.c os_auth/ssl.c shared.a
	$(CC) $(CFLAGS) -DLIBOPENSSL_ENABLED -c os_auth/ssl.c -o os_auth/ssl-2100.o
	$(CC) $(CFLAGS) -DLIBOPENSSL_ENABLED -o $@ tests/regressions/issue_2100_authd_ssl.c os_auth/ssl-2100.o \
		-Wl,--start-group shared.a os_regex.a os_net.a os_xml.a os_zlib.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto -lz

getalert_empty_filename: tests/regressions/getalert_empty_filename.c shared.a
	$(CC) $(CFLAGS) -o $@ tests/regressions/getalert_empty_filename.c \
		-Wl,--start-group shared.a os_regex.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto

# ANT-2026-KTGCYZ58: GetAlertData must not treat event text as headers.
issue_ktgcyz58_getalert_headers: \
		tests/regressions/issue_ktgcyz58_getalert_headers.c shared.a
	$(CC) $(CFLAGS) -o $@ tests/regressions/issue_ktgcyz58_getalert_headers.c \
		-Wl,--start-group shared.a os_regex.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto

# ANT-2026-35JW8GHU: forward-only day rollover + FileMon inode reopen.
issue_35jw8ghu_log_rollover: \
		tests/regressions/issue_35jw8ghu_log_rollover.c shared.a
	$(CC) $(CFLAGS) -o $@ tests/regressions/issue_35jw8ghu_log_rollover.c \
		-Wl,--start-group shared.a os_regex.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto

# ANT-2026-RNCE3SO7: read_syslog must truncate over-long lines (#913 follow-up).
issue_rnce3so7_syslog_long_line: \
		tests/regressions/issue_rnce3so7_syslog_long_line.c \
		logcollector/read_syslog.c shared.a
	$(CC) $(CFLAGS) -o $@ \
		tests/regressions/issue_rnce3so7_syslog_long_line.c \
		logcollector/read_syslog.c \
		-Wl,--start-group shared.a os_regex.a os_net.a os_xml.a os_zlib.a \
		-Wl,--end-group -lpcre2-8 -lm -lpthread -lz -lssl -lcrypto

# ANT-2026-H2JMYHXZ: mail subject cut must not underflow on leading '>'.
issue_h2jmyhxz_maild_subject_underflow: \
		tests/regressions/issue_h2jmyhxz_maild_subject_underflow.c \
		os_maild/mail_utils.c
	$(CC) $(CFLAGS) -I./os_maild -o $@ \
		tests/regressions/issue_h2jmyhxz_maild_subject_underflow.c \
		os_maild/mail_utils.c

# ANT-2026-3WKK50NE: OSHash must resist seed-independent Thue-Morse collisions.
issue_3wkk50ne_oshash_collisions: \
		tests/regressions/issue_3wkk50ne_oshash_collisions.c shared.a
	$(CC) $(CFLAGS) -o $@ \
		tests/regressions/issue_3wkk50ne_oshash_collisions.c \
		-Wl,--start-group shared.a os_regex.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto

# ANT-2026-8STI0Q1E: no linear integrity-DB scan on a healthy index miss.
issue_8sti0q1e_syscheck_linear_miss: \
		tests/regressions/issue_8sti0q1e_syscheck_linear_miss.c \
		analysisd/decoders/syscheck.c shared.a
	$(CC) $(CFLAGS) -DOSSEC_SYSCHECK_TEST \
		-DSYSCHECK_DIR=\"queue/syscheck\" \
		-I./analysisd -c analysisd/decoders/syscheck.c \
		-o analysisd/decoders/syscheck-8sti.o
	$(CC) $(CFLAGS) -DOSSEC_SYSCHECK_TEST \
		-DSYSCHECK_DIR=\"queue/syscheck\" -I./analysisd -o $@ \
		tests/regressions/issue_8sti0q1e_syscheck_linear_miss.c \
		analysisd/decoders/syscheck-8sti.o \
		shared/fim_sum_op.o \
		-Wl,--start-group shared.a os_regex.a os_net.a os_xml.a os_zlib.a \
		libcJSON.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lz -lssl -lcrypto

# ANT-2026-6WL10QQZ: directory walks stop at MAX_DIR_DEPTH.
# Rebuild common.c with a tiny limit so a short tree can prove the cap.
issue_6wl10qqz_dir_depth: \
		tests/regressions/issue_6wl10qqz_dir_depth.c \
		rootcheck/common.c shared.a os_crypto.a
	$(CC) $(CFLAGS) -DMAX_DIR_DEPTH=8 -I./rootcheck \
		-c rootcheck/common.c -o rootcheck/common-6wl.o
	$(CC) $(CFLAGS) -DMAX_DIR_DEPTH=8 -I./rootcheck -o $@ \
		tests/regressions/issue_6wl10qqz_dir_depth.c \
		rootcheck/common-6wl.o \
		-Wl,--start-group shared.a os_regex.a os_crypto.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto

# ANT-2026-TZMHDQ9M: syscheck decoder_info id must stay stable after handoff.
issue_tzmhdq9m_decoder_info_race: \
		tests/regressions/issue_tzmhdq9m_decoder_info_race.c \
		analysisd/decoders/syscheck.c shared.a
	$(CC) $(CFLAGS) -DOSSEC_SYSCHECK_TEST \
		-DSYSCHECK_DIR=\"queue/syscheck\" \
		-I./analysisd -c analysisd/decoders/syscheck.c \
		-o analysisd/decoders/syscheck-tzmh.o
	$(CC) $(CFLAGS) -DOSSEC_SYSCHECK_TEST \
		-DSYSCHECK_DIR=\"queue/syscheck\" -I./analysisd -o $@ \
		tests/regressions/issue_tzmhdq9m_decoder_info_race.c \
		analysisd/decoders/syscheck-tzmh.o \
		shared/fim_sum_op.o \
		-Wl,--start-group shared.a os_regex.a os_net.a os_xml.a os_zlib.a \
		libcJSON.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lz -lssl -lcrypto

# ANT-2026-2D3XMA3W: *_FP setters free prior heap value on overwrite.
issue_2d3xma3w_decoder_field_leak: \
		tests/regressions/issue_2d3xma3w_decoder_field_leak.c \
		analysisd/decoders/decoder.c shared.a
	$(CC) $(CFLAGS) -I./analysisd -c analysisd/decoders/decoder.c \
		-o analysisd/decoders/decoder-2d3.o
	$(CC) $(CFLAGS) -I./analysisd -o $@ \
		tests/regressions/issue_2d3xma3w_decoder_field_leak.c \
		analysisd/decoders/decoder-2d3.o \
		-Wl,--wrap=free \
		-Wl,--start-group shared.a os_regex.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto

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
		-lpcre2-8 -lm -lpthread -lssl -lcrypto

issue_ar_location_injection: tests/regressions/issue_ar_location_injection.c shared.a
	$(CC) $(CFLAGS) -o $@ tests/regressions/issue_ar_location_injection.c \
		-Wl,--start-group shared.a os_regex.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto

issue_ads_stream_overflow: tests/regressions/issue_ads_stream_overflow.c rootcheck/win-common.c
	$(CC) $(CFLAGS) -I./rootcheck -o $@ tests/regressions/issue_ads_stream_overflow.c \
		rootcheck/win-common.c

issue_win_parent_folder: tests/regressions/issue_win_parent_folder.c shared.a
	$(CC) $(CFLAGS) -o $@ tests/regressions/issue_win_parent_folder.c \
		-Wl,--start-group shared.a os_regex.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto

issue_syscheck_prefix_sum_size: tests/regressions/issue_syscheck_prefix_sum_size.c \
		analysisd/decoders/syscheck_db_entry.h headers/defs.h
	$(CC) $(CFLAGS) -I./analysisd -o $@ tests/regressions/issue_syscheck_prefix_sum_size.c

issue_bind_unix_chmod_race: tests/regressions/issue_bind_unix_chmod_race.c os_net.a shared.a
	$(CC) $(CFLAGS) -o $@ tests/regressions/issue_bind_unix_chmod_race.c \
		-Wl,--wrap=bind \
		-Wl,--start-group shared.a os_regex.a os_net.a os_xml.a os_zlib.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lz -lssl -lcrypto

issue_read_dir_path_overflow: tests/regressions/issue_read_dir_path_overflow.c \
		syscheckd/syscheck_path.c
	$(CC) $(CFLAGS) -I./syscheckd -o $@ tests/regressions/issue_read_dir_path_overflow.c \
		syscheckd/syscheck_path.c

issue_ossecalert_field_injection: tests/regressions/issue_ossecalert_field_injection.c \
		logcollector/ossecalert_field.c
	$(CC) $(CFLAGS) -I./logcollector -o $@ tests/regressions/issue_ossecalert_field_injection.c \
		logcollector/ossecalert_field.c

# ANT-2026-3VN001L2: prefilter_cmd retired (no popen sink).
issue_3vn001l2_prefilter_retire: \
		tests/regressions/issue_3vn001l2_prefilter_retire.c \
		os_crypto/md5_sha1/md5_sha1_op.c shared.a os_crypto.a
	$(CC) $(CFLAGS) -o $@ \
		tests/regressions/issue_3vn001l2_prefilter_retire.c \
		-Wl,--start-group shared.a os_crypto.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto

# ANT-2026-96VSXF8B: refuse symlink / non-root report_changes store.
# DEFAULTDIR="." so the harness can chdir into a temp tree for queue/diff.
issue_96vsxf8b_diff_store_symlink: \
		tests/regressions/issue_96vsxf8b_diff_store_symlink.c \
		syscheckd/seechanges.c shared.a os_crypto.a
	$(CC) $(CFLAGS) -DDEFAULTDIR=\".\" -I./syscheckd -o $@ \
		tests/regressions/issue_96vsxf8b_diff_store_symlink.c \
		syscheckd/seechanges.c \
		-Wl,--start-group shared.a os_crypto.a os_regex.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto

# ANT-2026-S3EU4A19: is_valid_crawler must not block on DNS.
issue_s3eu4a19_crawler_dns: \
		tests/regressions/issue_s3eu4a19_crawler_dns.c \
		analysisd/compiled_rules/generic_samples.c \
		analysisd/eventinfo.c analysisd/eventinfo_list.c shared.a
	$(CC) $(CFLAGS) -I./analysisd -o $@ \
		tests/regressions/issue_s3eu4a19_crawler_dns.c \
		analysisd/compiled_rules/generic_samples.c \
		analysisd/eventinfo.c analysisd/eventinfo_list.c \
		-Wl,--start-group shared.a os_regex.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto

issue_rootcheck_json_empty_name: tests/regressions/issue_rootcheck_json_empty_name.c \
		analysisd/format/json_extended.c libcJSON.a shared.a
	$(CC) $(CFLAGS) -I./analysisd -I./external/cJSON -o $@ \
		tests/regressions/issue_rootcheck_json_empty_name.c \
		analysisd/format/json_extended.c \
		-Wl,--start-group shared.a os_regex.a libcJSON.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto

issue_rootcheck_json_match_overflow: tests/regressions/issue_rootcheck_json_match_overflow.c \
		analysisd/format/json_extended.c libcJSON.a shared.a
	$(CC) $(CFLAGS) -I./analysisd -I./external/cJSON -o $@ \
		tests/regressions/issue_rootcheck_json_match_overflow.c \
		analysisd/format/json_extended.c \
		-Wl,--start-group shared.a os_regex.a libcJSON.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto

issue_str_cut_overflow: tests/regressions/issue_str_cut_overflow.c \
		analysisd/format/json_extended.c libcJSON.a shared.a
	$(CC) $(CFLAGS) -I./analysisd -I./external/cJSON -o $@ \
		tests/regressions/issue_str_cut_overflow.c \
		analysisd/format/json_extended.c \
		-Wl,--start-group shared.a os_regex.a libcJSON.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto

issue_strtok_race: tests/regressions/issue_strtok_race.c \
		analysisd/format/json_extended.c libcJSON.a shared.a
	$(CC) $(CFLAGS) -I./analysisd -I./external/cJSON -o $@ \
		tests/regressions/issue_strtok_race.c \
		analysisd/format/json_extended.c \
		-Wl,--start-group shared.a os_regex.a libcJSON.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto

# Open a cwd-local ar.conf (defs.h redefines DEFAULTARPATH). Compile at -O0
# so a missing bound is more likely to show up in GetCommandbyName results.
issue_mon246f3_execd_ar_overflow: \
		tests/regressions/issue_mon246f3_execd_ar_overflow.c \
		os_execd/exec.c shared.a
	sed -e 's/fopen(DEFAULTARPATH/fopen("ar.conf"/g' \
		-e 's/AR_BINDIRPATH/"active-response\/bin"/g' \
		os_execd/exec.c > os_execd/exec-mon246f3.c
	$(CC) $(CFLAGS) -O0 -I./os_execd -c os_execd/exec-mon246f3.c \
		-o os_execd/exec-mon246f3.o
	$(CC) $(CFLAGS) -I./os_execd -o $@ \
		tests/regressions/issue_mon246f3_execd_ar_overflow.c \
		os_execd/exec-mon246f3.o \
		-Wl,--start-group shared.a os_regex.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto
	rm -f os_execd/exec-mon246f3.c

issue_fb1hyskp_pagerduty_alertlog: \
		tests/regressions/issue_fb1hyskp_pagerduty_alertlog.sh \
		../active-response/ossec-pagerduty.sh
	@printf '%s\n' '#!/bin/sh' \
		'exec bash "$$(dirname "$$0")/tests/regressions/issue_fb1hyskp_pagerduty_alertlog.sh" "$$@"' > $@
	@chmod +x $@
	./$@

issue_ant2026_ar_scripts: \
		tests/regressions/issue_ant2026_ar_scripts.sh \
		../active-response/ossec-pagerduty.sh \
		../active-response/ossec-slack.sh \
		../active-response/ossec-tweeter.sh \
		../active-response/host-deny.sh \
		../active-response/firewalls/ipfw_mac.sh \
		../active-response/cloudflare-ban.sh
	@printf '%s\n' '#!/bin/sh' \
		'exec bash "$$(dirname "$$0")/tests/regressions/issue_ant2026_ar_scripts.sh" "$$@"' > $@
	@chmod +x $@
	./$@

# Expose audit_send_msg and record final join index for the harness.
issue_ud31vlyl_audit_oob: \
		tests/regressions/issue_ud31vlyl_audit_oob.c \
		logcollector/read_audit.c shared.a
	sed -e 's/^static void audit_send_msg/size_t audit_last_n;\nvoid audit_send_msg/' \
		-e 's/message\[n\] = '\''\\0'\'';/audit_last_n = n; message[n] = '\''\\0'\'';/' \
		logcollector/read_audit.c > logcollector/read_audit-ud31vlyl.c
	$(CC) $(CFLAGS) -I./logcollector -c logcollector/read_audit-ud31vlyl.c \
		-o logcollector/read_audit-ud31vlyl.o
	$(CC) $(CFLAGS) -I./logcollector -o $@ \
		tests/regressions/issue_ud31vlyl_audit_oob.c \
		logcollector/read_audit-ud31vlyl.o \
		-Wl,--start-group shared.a os_regex.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto
	rm -f logcollector/read_audit-ud31vlyl.c

issue_m5jt0jcl_authd_key_rng: \
		tests/regressions/issue_m5jt0jcl_authd_key_rng.c \
		addagent/validate.c shared.a os_crypto.a
	$(CC) $(CFLAGS) -DAUTH_FILE=\"client.keys\" -c addagent/validate.c \
		-o addagent/validate-m5jt0jcl.o
	$(CC) $(CFLAGS) -o $@ tests/regressions/issue_m5jt0jcl_authd_key_rng.c \
		addagent/validate-m5jt0jcl.o \
		-Wl,--wrap=randombytes_try -Wl,--wrap=isChroot \
		-Wl,--start-group shared.a os_regex.a os_crypto.a os_net.a os_xml.a os_zlib.a libcJSON.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto -lz

# ANT-2026-C186EP5N: nodiff_size must be per <nodiff> node (like ign_size).
# Compile syscheck-config.c into the binary so the harness does not depend on
# a stale config.a member; pull the rest of config via config.a.
# (syscheck_remote_cmd.c removed with prefilter_cmd retirement, ANT-2026-3VN001L2.)
issue_c186ep5n_nodiff_size: \
		tests/regressions/issue_c186ep5n_nodiff_size.c \
		config/syscheck-config.c shared.a
	$(CC) $(CFLAGS) -I./config -o $@ \
		tests/regressions/issue_c186ep5n_nodiff_size.c \
		config/syscheck-config.c \
		-Wl,--start-group shared.a os_regex.a os_xml.a os_net.a config.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto

# Compile localfile-config.c into the binary so the harness does not depend
# on a possibly stale config.a member from an earlier server build.
issue_dnxhhf88_localfile_double_free: \
		tests/regressions/issue_dnxhhf88_localfile_double_free.c \
		config/localfile-config.c shared.a
	$(CC) $(CFLAGS) -I./config -o $@ \
		tests/regressions/issue_dnxhhf88_localfile_double_free.c \
		config/localfile-config.c \
		-Wl,--start-group shared.a os_regex.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto

# Relative queue paths so the harness can chdir into a temp tree.
HT_PATH_CFLAGS = -DAGENTINFO_DIR=\"queue/agent-info\" -DDIFF_DIR=\"queue/diff\"
issue_hostname_path_traversal: tests/regressions/issue_hostname_path_traversal.c \
		analysisd/decoders/plugins/ossecalert_decoder.c \
		analysisd/dodiff.c analysisd/eventinfo.c analysisd/eventinfo_list.c shared.a
	$(CC) $(CFLAGS) $(HT_PATH_CFLAGS) -I./analysisd \
		-c analysisd/decoders/plugins/ossecalert_decoder.c \
		-o analysisd/decoders/plugins/ossecalert_decoder-ht.o
	$(CC) $(CFLAGS) $(HT_PATH_CFLAGS) -I./analysisd \
		-c analysisd/dodiff.c -o analysisd/dodiff-ht.o
	$(CC) $(CFLAGS) -I./analysisd -c analysisd/eventinfo.c -o analysisd/eventinfo-ht.o
	$(CC) $(CFLAGS) -I./analysisd -c analysisd/eventinfo_list.c -o analysisd/eventinfo_list-ht.o
	$(CC) $(CFLAGS) $(HT_PATH_CFLAGS) -I./analysisd -o $@ \
		tests/regressions/issue_hostname_path_traversal.c \
		analysisd/decoders/plugins/ossecalert_decoder-ht.o \
		analysisd/dodiff-ht.o analysisd/eventinfo-ht.o analysisd/eventinfo_list-ht.o \
		-Wl,--start-group shared.a os_regex.a os_net.a os_xml.a os_zlib.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lz -lssl -lcrypto

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
		analysisd/eventinfo_list-1668.o analysisd/accumulator-1668.o \
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
		os_crypto/md5/md5_op-empty.o \
		analysisd/decoders/plugins/ossecalert_decoder-ht.o \
		analysisd/dodiff-ht.o \
		analysisd/eventinfo-ht.o \
		analysisd/eventinfo_list-ht.o \
		addagent/validate-m5jt0jcl.o \
		os_execd/exec-mon246f3.o \
		os_execd/exec-mon246f3.c \
		logcollector/read_audit-ud31vlyl.o \
		logcollector/read_audit-ud31vlyl.c \
		analysisd/decoders/syscheck-8sti.o \
		rootcheck/common-6wl.o \
		analysisd/decoders/decoder-2d3.o \
		analysisd/decoders/syscheck-tzmh.o
