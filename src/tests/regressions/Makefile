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
	issue_fbj3la25_rids_counter_reload \
	issue_ja2nxew1_reject_log \
	issue_qy1shlvv_syslog_tcp_idle \
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
	issue_1o4bcxpr_createpid \
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
	issue_2138nb95_report_changes_symlink \
	issue_j8xf7lcx_file_max_size \
	issue_4t9f7xiq_diff_store \
	issue_mbh20u16_dirfd_walk \
	issue_s3eu4a19_crawler_dns \
	issue_ktgcyz58_getalert_headers \
	issue_35jw8ghu_log_rollover \
	issue_rnce3so7_syslog_long_line \
	issue_h2jmyhxz_maild_subject_underflow \
	issue_3wkk50ne_oshash_collisions \
	issue_8sti0q1e_syscheck_linear_miss \
	issue_6wl10qqz_dir_depth \
	issue_2d3xma3w_decoder_field_leak \
	issue_tzmhdq9m_decoder_info_race \
	issue_rbaky685_syscheck_slot_exhaustion \
	issue_j9qhsfrd_fts_location_newline \
	issue_pwed0r2h_demux_push_wait \
	issue_4ojpklvk_fts_store_size \
	issue_mqq5w9cu_ig_queue \
	issue_grfznie0_csyslog_spaces \
	issue_dj9ev0kp_json_overlong \
	issue_913_nul_in_log \
	issue_k99okmjp_journald_rotation \
	issue_9hsm6ma8_long_line_pieces \
	issue_rer9koy9_popen_keep_command \
	issue_1yeqlyn9_journald_field_bounds \
	issue_54azkai7_max_lines \
	issue_9lqq1bms_osregex_bytes \
	issue_7me0g28i_decoder_redos \
	issue_pund7vet_ar_conf_symlink \
	issue_myqz0org_ossec_alert_leak \
	issue_5t5qgo1d_authd_agent_limit \
	issue_zo60j6e9_authd_pass \
	issue_rxuwsl9z_csyslog_escape \
	issue_sint56ko_dbd_alertid_sqli \
	issue_snxgrhga_execd_null_deref \
	issue_2lgojr12_execd_user_dup \
	issue_u9risggm_fopen_regular \
	issue_kzajsoet_syscheck_fifo \
	issue_1hue1bmj_ossecalert_drain \
	issue_9uqvlix8_ifconfig_inject \
	issue_cdykrrho_comma_dir \
	issue_w5qjuux2_symlink_race \
	issue_ae2i21jq_pid_sleep \
	issue_b5y9piu1_policy_owner \
	issue_x2iu8bsu_maild_donotgroup \
	issue_czg2brko_maild_gran_split \
	issue_rxknzj1n_smtp_dot_escape \
	issue_739qmecr_readsecmsg_uncompress \
	issue_2nlm3gpl_crypto_method_auth

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

# ANT-2026-FBJ3LA25: persist agent rids before OS_FreeKeys (reload/shutdown).
issue_fbj3la25_rids_counter_reload: tests/regressions/issue_fbj3la25_rids_counter_reload.c os_crypto.a shared.a
	$(CC) $(CFLAGS) -o $@ tests/regressions/issue_fbj3la25_rids_counter_reload.c \
		-Wl,--start-group shared.a os_regex.a os_crypto.a os_net.a os_xml.a os_zlib.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto -lz

# ANT-2026-JA2NXEW1: remoted pre-auth rejection logging must burst-limit.
issue_ja2nxew1_reject_log: tests/regressions/issue_ja2nxew1_reject_log.c \
		remoted/reject_log.c shared.a
	$(CC) $(CFLAGS) -I./remoted -o $@ \
		tests/regressions/issue_ja2nxew1_reject_log.c remoted/reject_log.c \
		-Wl,--start-group shared.a os_regex.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto


# ANT-2026-QY1SHLVV: syslog TCP workers must release idle/dead clients.
issue_qy1shlvv_syslog_tcp_idle: tests/regressions/issue_qy1shlvv_syslog_tcp_idle.c \
		remoted/syslog_tcp_idle.c shared.a
	$(CC) $(CFLAGS) -I./remoted -o $@ \
		tests/regressions/issue_qy1shlvv_syslog_tcp_idle.c remoted/syslog_tcp_idle.c \
		-Wl,--start-group shared.a os_regex.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto


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

# ANT-2026-1O4BCXPR: CreatePID must not follow a symlink in var/run.
issue_1o4bcxpr_createpid: \
		tests/regressions/issue_1o4bcxpr_createpid.c shared/file_op.c shared.a
	$(CC) $(CFLAGS) -DDEFAULTDIR=\".\" -o $@ \
		tests/regressions/issue_1o4bcxpr_createpid.c shared/file_op.c \
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
		logcollector/read_syslog.c logcollector/logr_fgets.c shared.a
	$(CC) $(CFLAGS) -o $@ \
		tests/regressions/issue_rnce3so7_syslog_long_line.c \
		logcollector/read_syslog.c logcollector/logr_fgets.c \
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

# ANT-2026-4OJPKLVK: FTS store must drop oldest keys past fts_store_size.
issue_4ojpklvk_fts_store_size: \
		tests/regressions/issue_4ojpklvk_fts_store_size.c \
		analysisd/fts.c shared.a
	$(CC) $(CFLAGS) -DTESTRULE -DOSSEC_FTS_TEST -I./analysisd \
		-c analysisd/fts.c -o analysisd/fts-4ojp.o
	$(CC) $(CFLAGS) -DTESTRULE -DOSSEC_FTS_TEST -I./analysisd -o $@ \
		tests/regressions/issue_4ojpklvk_fts_store_size.c \
		analysisd/fts-4ojp.o \
		-Wl,--start-group shared.a os_regex.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto

# ANT-2026-MQQ5W9CU: ig-queue must drop oldest ignore records past ig_list_size.
issue_mqq5w9cu_ig_queue: \
		tests/regressions/issue_mqq5w9cu_ig_queue.c \
		analysisd/fts.c shared.a
	$(CC) $(CFLAGS) -DTESTRULE -DOSSEC_IG_TEST -I./analysisd \
		-c analysisd/fts.c -o analysisd/fts-mqq5.o
	$(CC) $(CFLAGS) -DTESTRULE -DOSSEC_IG_TEST -I./analysisd -o $@ \
		tests/regressions/issue_mqq5w9cu_ig_queue.c \
		analysisd/fts-mqq5.o \
		-Wl,--start-group shared.a os_regex.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto

# ANT-2026-GRFZNIE0: default csyslog format needs two spaces before log text.
issue_grfznie0_csyslog_spaces: \
		tests/regressions/issue_grfznie0_csyslog_spaces.c \
		os_csyslogd/alert.c os_csyslogd/escape.c shared.a
	$(CC) $(CFLAGS) -I./os_csyslogd -I./external/cJSON \
		-c os_csyslogd/alert.c -o os_csyslogd/alert-grfz.o
	$(CC) $(CFLAGS) -I./os_csyslogd -I./external/cJSON \
		-c os_csyslogd/escape.c -o os_csyslogd/escape-grfz.o
	$(CC) $(CFLAGS) -I./os_csyslogd -I./external/cJSON -o $@ \
		tests/regressions/issue_grfznie0_csyslog_spaces.c \
		os_csyslogd/alert-grfz.o os_csyslogd/escape-grfz.o \
		-Wl,--start-group shared.a os_regex.a libcJSON.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto

# ANT-2026-DJ9EV0KP: overlong alerts.json records must still parse.
issue_dj9ev0kp_json_overlong: \
		tests/regressions/issue_dj9ev0kp_json_overlong.c \
		os_csyslogd/json-queue.c shared.a
	$(CC) $(CFLAGS) -I./os_csyslogd -I./external/cJSON \
		-c os_csyslogd/json-queue.c -o os_csyslogd/json-queue-dj9.o
	$(CC) $(CFLAGS) -I./os_csyslogd -I./external/cJSON -o $@ \
		tests/regressions/issue_dj9ev0kp_json_overlong.c \
		os_csyslogd/json-queue-dj9.o \
		-Wl,--start-group shared.a os_regex.a libcJSON.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto

# ANT-2026-WIHVHVO0 / #913: embedded NUL must not stall/drop log readers.
NUL_READERS = logcollector/read_modsec_audit.c logcollector/read_audit.c \
	logcollector/read_multiline.c logcollector/read_mysql_log.c

issue_913_nul_in_log: tests/regressions/issue_913_nul_in_log.c $(NUL_READERS) \
		logcollector/logr_fgets.c shared.a
	$(CC) $(CFLAGS) -I./logcollector -o $@ \
		tests/regressions/issue_913_nul_in_log.c $(NUL_READERS) \
		logcollector/logr_fgets.c $(BASIC_LIBS)

# ANT-2026-K99OKMJP: journald reader must process inotify after rotation.
issue_k99okmjp_journald_rotation: \
		tests/regressions/issue_k99okmjp_journald_rotation.c \
		logcollector/read_journald.c logcollector/logr_fgets.c shared.a
	$(CC) $(CFLAGS) -DHAVE_SYSTEMD -I./logcollector \
		-I./tests/regressions/stubs -o $@ \
		tests/regressions/issue_k99okmjp_journald_rotation.c \
		logcollector/read_journald.c logcollector/logr_fgets.c $(BASIC_LIBS)

# ANT-2026-9HSM6MA8: ignore every piece of an over-long line until its newline.
LONG_LINE_READERS = logcollector/read_djb_multilog.c logcollector/read_mysql_log.c \
	logcollector/read_mssql_log.c logcollector/read_postgresql_log.c \
	logcollector/read_multiline_indented.c

issue_9hsm6ma8_long_line_pieces: \
		tests/regressions/issue_9hsm6ma8_long_line_pieces.c \
		$(LONG_LINE_READERS) logcollector/logr_fgets.c shared.a
	$(CC) $(CFLAGS) -I./logcollector -o $@ \
		tests/regressions/issue_9hsm6ma8_long_line_pieces.c \
		$(LONG_LINE_READERS) logcollector/logr_fgets.c $(BASIC_LIBS)

# ANT-2026-RER9KOY9: failed popen must not permanently disable command monitors.
issue_rer9koy9_popen_keep_command: \
		tests/regressions/issue_rer9koy9_popen_keep_command.c \
		logcollector/read_command.c logcollector/read_fullcommand.c shared.a
	$(CC) $(CFLAGS) -I./logcollector -o $@ \
		tests/regressions/issue_rer9koy9_popen_keep_command.c \
		logcollector/read_command.c logcollector/read_fullcommand.c \
		$(BASIC_LIBS) -Wl,--wrap=popen -Wl,--wrap=pclose

# ANT-2026-1YEQLYN9: journal field blobs are length-bounded, not C strings.
issue_1yeqlyn9_journald_field_bounds: \
		tests/regressions/issue_1yeqlyn9_journald_field_bounds.c \
		logcollector/read_journald.c logcollector/logr_fgets.c shared.a
	$(CC) $(CFLAGS) -DHAVE_SYSTEMD -I./logcollector \
		-I./tests/regressions/stubs -o $@ \
		tests/regressions/issue_1yeqlyn9_journald_field_bounds.c \
		logcollector/read_journald.c logcollector/logr_fgets.c $(BASIC_LIBS)

# ANT-2026-54AZKAI7: one file must not starve the others in a single visit.
issue_54azkai7_max_lines: \
		tests/regressions/issue_54azkai7_max_lines.c \
		logcollector/read_syslog.c logcollector/logr_fgets.c shared.a
	$(CC) $(CFLAGS) -I./logcollector -o $@ \
		tests/regressions/issue_54azkai7_max_lines.c \
		logcollector/read_syslog.c logcollector/logr_fgets.c $(BASIC_LIBS)

# ANT-2026-9LQQ1BMS: classic OSRegex/OSMatch must match non-UTF-8 bytes.
issue_9lqq1bms_osregex_bytes: \
		tests/regressions/issue_9lqq1bms_osregex_bytes.c os_regex.a shared.a
	$(CC) $(CFLAGS) -o $@ \
		tests/regressions/issue_9lqq1bms_osregex_bytes.c $(BASIC_LIBS)

# ANT-2026-7ME0G28I: windows1/barracuda-svf1 decoder patterns must not ReDoS.
issue_7me0g28i_decoder_redos: \
		tests/regressions/issue_7me0g28i_decoder_redos.c
	$(CC) $(CFLAGS) -o $@ \
		tests/regressions/issue_7me0g28i_decoder_redos.c -lpcre2-8

# ANT-2026-PUND7VET: ar.conf rewrite must not follow a group-planted symlink.
# Rebuild active-response objects with a private DEFAULTDIR so the test never
# touches a real /var/ossec tree; drop the stock active-response.o from config.a.
PUND_DEFAULTDIR ?= /tmp/ossec-pund7vet-ar
issue_pund7vet_ar_conf_symlink: \
		tests/regressions/issue_pund7vet_ar_conf_symlink.c \
		analysisd/active-response.c config/active-response.c \
		config.a shared.a os_xml.a os_regex.a
	@cp -f config.a config-pund.a
	@$(AR) d config-pund.a active-response.o >/dev/null
	$(CC) $(CFLAGS) -I./analysisd -DPUND_DEFAULTDIR=\"$(PUND_DEFAULTDIR)\" \
		-DDEFAULTDIR=\"$(PUND_DEFAULTDIR)\" \
		-o $@ tests/regressions/issue_pund7vet_ar_conf_symlink.c \
		analysisd/active-response.c config/active-response.c \
		-Wl,--start-group config-pund.a shared.a os_xml.a os_regex.a os_net.a \
		-Wl,--end-group -lpcre2-8 -lm -lpthread -lssl -lcrypto

# ANT-2026-PWED0R2H: demux/shard must not soak on agent-controlled queues.
issue_pwed0r2h_demux_push_wait: \
		tests/regressions/issue_pwed0r2h_demux_push_wait.c \
		analysisd/pipeline_push_wait.h
	$(CC) $(CFLAGS) -I./analysisd -o $@ \
		tests/regressions/issue_pwed0r2h_demux_push_wait.c

# ANT-2026-J9QHSFRD: newline in location must not forge FTS / alert lines.
issue_j9qhsfrd_fts_location_newline: \
		tests/regressions/issue_j9qhsfrd_fts_location_newline.c \
		analysisd/cleanevent.c shared.a
	$(CC) $(CFLAGS) -I./analysisd -DTESTRULE -c analysisd/cleanevent.c \
		-o analysisd/cleanevent-j9qh.o
	$(CC) $(CFLAGS) -I./analysisd -o $@ \
		tests/regressions/issue_j9qhsfrd_fts_location_newline.c \
		analysisd/cleanevent-j9qh.o \
		-Wl,--start-group shared.a os_regex.a os_net.a os_xml.a os_zlib.a \
		-Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lz -lssl -lcrypto

# ANT-2026-RBAKY685: forged locations must not take syscheck/rootcheck DB slots.
issue_rbaky685_syscheck_slot_exhaustion: \
		tests/regressions/issue_rbaky685_syscheck_slot_exhaustion.c \
		analysisd/decoders/syscheck.c analysisd/decoders/rootcheck.c shared.a
	$(CC) $(CFLAGS) -DOSSEC_SYSCHECK_TEST \
		-DSYSCHECK_DIR=\"queue/syscheck\" \
		-I./analysisd -c analysisd/decoders/syscheck.c \
		-o analysisd/decoders/syscheck-rbaky.o
	$(CC) $(CFLAGS) -DOSSEC_ROOTCHECK_TEST \
		-DROOTCHECK_DIR=\"queue/rootcheck\" \
		-I./analysisd -c analysisd/decoders/rootcheck.c \
		-o analysisd/decoders/rootcheck-rbaky.o
	$(CC) $(CFLAGS) -DOSSEC_SYSCHECK_TEST -DOSSEC_ROOTCHECK_TEST \
		-DSYSCHECK_DIR=\"queue/syscheck\" \
		-DROOTCHECK_DIR=\"queue/rootcheck\" \
		-I./analysisd -o $@ \
		tests/regressions/issue_rbaky685_syscheck_slot_exhaustion.c \
		analysisd/decoders/syscheck-rbaky.o \
		analysisd/decoders/rootcheck-rbaky.o \
		shared/fim_sum_op.o \
		-Wl,--start-group shared.a os_regex.a os_net.a os_xml.a os_zlib.a \
		libcJSON.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lz -lssl -lcrypto

# ANT-2026-SNXGRHGA: execd must not strcmp NULL IP on incomplete AR requests.
issue_snxgrhga_execd_null_deref: \
		tests/regressions/issue_snxgrhga_execd_null_deref.c \
		os_execd/timeout_dup.c shared.a
	$(CC) $(CFLAGS) -I./os_execd -c os_execd/timeout_dup.c \
		-o os_execd/timeout_dup-snx.o
	$(CC) $(CFLAGS) -I./os_execd -o $@ \
		tests/regressions/issue_snxgrhga_execd_null_deref.c \
		os_execd/timeout_dup-snx.o \
		-Wl,--start-group shared.a os_regex.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto

# ANT-2026-2LGOJR12: user-keyed AR dup check must compare argv[2] (user).
issue_2lgojr12_execd_user_dup: \
		tests/regressions/issue_2lgojr12_execd_user_dup.c \
		os_execd/timeout_dup.c shared.a
	$(CC) $(CFLAGS) -I./os_execd -c os_execd/timeout_dup.c \
		-o os_execd/timeout_dup-2lg.o
	$(CC) $(CFLAGS) -I./os_execd -o $@ \
		tests/regressions/issue_2lgojr12_execd_user_dup.c \
		os_execd/timeout_dup-2lg.o \
		-Wl,--start-group shared.a os_regex.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto

# ANT-2026-U9RISGGM: fopen_regular must refuse FIFO/device without hanging.
issue_u9risggm_fopen_regular: tests/regressions/issue_u9risggm_fopen_regular.c shared.a
	$(CC) $(CFLAGS) -o $@ tests/regressions/issue_u9risggm_fopen_regular.c \
		-Wl,--start-group shared.a os_regex.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto

# ANT-2026-KZAJSOET: hash helpers must refuse FIFO without hanging.
# ANT-2026-B5Y9PIU1: refuse non-root / group-writable rootcheck policies.
issue_b5y9piu1_policy_owner: \
		tests/regressions/issue_b5y9piu1_policy_owner.c \
		rootcheck/rk_policy_open.c shared.a
	$(CC) $(CFLAGS) -DOSSECHIDS -I./rootcheck -o $@ \
		tests/regressions/issue_b5y9piu1_policy_owner.c \
		rootcheck/rk_policy_open.c $(BASIC_LIBS)

# ANT-2026-9UQVLIX8: ifconfig interface names must be shell-quoted.
issue_9uqvlix8_ifconfig_inject: \
		tests/regressions/issue_9uqvlix8_ifconfig_inject.c \
		rootcheck/check_rc_if.c shared.a
	$(CC) $(CFLAGS) -I./rootcheck -o $@ \
		tests/regressions/issue_9uqvlix8_ifconfig_inject.c \
		rootcheck/check_rc_if.c $(BASIC_LIBS)

# ANT-2026-CDYKRRHO: readdir paths must not be split at commas.
issue_cdykrrho_comma_dir: \
		tests/regressions/issue_cdykrrho_comma_dir.c \
		rootcheck/common.c shared.a os_crypto.a
	$(CC) $(CFLAGS) -I./rootcheck -o $@ \
		tests/regressions/issue_cdykrrho_comma_dir.c \
		rootcheck/common.c \
		-Wl,--start-group shared.a os_regex.a os_crypto.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto

# ANT-2026-W5QJUUX2: rootcheck must look entries up relative to the open
# parent DIR (fstatat/openat/fdopendir, O_NOFOLLOW/AT_SYMLINK_NOFOLLOW)
# instead of by path, so a renamed-to-symlink-ring directory cannot divert
# the walker or hang it.
issue_w5qjuux2_symlink_race: \
		tests/regressions/issue_w5qjuux2_symlink_race.c \
		rootcheck/common.c shared.a os_crypto.a
	$(CC) $(CFLAGS) -I./rootcheck -o $@ \
		tests/regressions/issue_w5qjuux2_symlink_race.c \
		rootcheck/common.c \
		-Wl,--start-group shared.a os_regex.a os_crypto.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto

# ANT-2026-AE2I21JQ: PID-scan sleep budget.
issue_ae2i21jq_pid_sleep: \
		tests/regressions/issue_ae2i21jq_pid_sleep.c \
		rootcheck/rk_pid_budget.c
	$(CC) $(CFLAGS) -I./rootcheck -o $@ \
		tests/regressions/issue_ae2i21jq_pid_sleep.c \
		rootcheck/rk_pid_budget.c

# ANT-2026-1HUE1BMJ: ossecalert must drain every alert in one poll.
issue_1hue1bmj_ossecalert_drain: \
		tests/regressions/issue_1hue1bmj_ossecalert_drain.c \
		logcollector/read_ossecalert.c logcollector/ossecalert_field.c \
		logcollector/logr_fgets.c shared.a
	$(CC) $(CFLAGS) -I./logcollector -o $@ \
		tests/regressions/issue_1hue1bmj_ossecalert_drain.c \
		logcollector/read_ossecalert.c logcollector/ossecalert_field.c \
		logcollector/logr_fgets.c $(BASIC_LIBS)

issue_kzajsoet_syscheck_fifo: tests/regressions/issue_kzajsoet_syscheck_fifo.c \
		shared.a os_crypto.a
	$(CC) $(CFLAGS) -o $@ tests/regressions/issue_kzajsoet_syscheck_fifo.c \
		-Wl,--start-group shared.a os_crypto.a os_zlib.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto -lz


# ANT-2026-X2IU8BSU: batch commit must promote held DONOTGROUP marks, not wipe them.
issue_x2iu8bsu_maild_donotgroup: \
		tests/regressions/issue_x2iu8bsu_maild_donotgroup.c \
		os_maild/mail_gran.c shared.a
	$(CC) $(CFLAGS) -I./os_maild -o $@ \
		tests/regressions/issue_x2iu8bsu_maild_donotgroup.c \
		os_maild/mail_gran.c \
		-Wl,--start-group shared.a os_regex.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto

# ANT-2026-CZG2BRKO: split grouped mail by per-alert FULL_FORMAT recipient set.
issue_czg2brko_maild_gran_split: \
		tests/regressions/issue_czg2brko_maild_gran_split.c \
		os_maild/mail_list.c shared.a
	$(CC) $(CFLAGS) -I./os_maild -o $@ \
		tests/regressions/issue_czg2brko_maild_gran_split.c \
		os_maild/mail_list.c \
		-Wl,--start-group shared.a os_regex.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto

# ANT-2026-RXKNZJ1N: SMTP / sendmail body must escape leading dots (RFC 5321).
issue_rxknzj1n_smtp_dot_escape: \
		tests/regressions/issue_rxknzj1n_smtp_dot_escape.c \
		os_maild/mail_utils.c
	$(CC) $(CFLAGS) -I./os_maild -o $@ \
		tests/regressions/issue_rxknzj1n_smtp_dot_escape.c \
		os_maild/mail_utils.c

# ANT-2026-SINT56KO: ossec-dbd must escape alertid (and tld/srcgeoip) for INSERT.
issue_sint56ko_dbd_alertid_sqli: \
		tests/regressions/issue_sint56ko_dbd_alertid_sqli.c \
		os_dbd/alert.c os_dbd/db_op.c shared.a
	$(CC) $(CFLAGS) -I./os_dbd -c os_dbd/alert.c -o os_dbd/alert-sint.o
	$(CC) $(CFLAGS) -I./os_dbd -c os_dbd/db_op.c -o os_dbd/db_op-sint.o
	$(CC) $(CFLAGS) -I./os_dbd -o $@ \
		tests/regressions/issue_sint56ko_dbd_alertid_sqli.c \
		os_dbd/alert-sint.o os_dbd/db_op-sint.o \
		-Wl,--start-group shared.a os_regex.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto

# ANT-2026-RXUWSL9Z: Splunk/CEF field escaping for csyslogd.
issue_rxuwsl9z_csyslog_escape: \
		tests/regressions/issue_rxuwsl9z_csyslog_escape.c \
		os_csyslogd/escape.c shared.a
	$(CC) $(CFLAGS) -I./os_csyslogd -I./external/cJSON \
		-c os_csyslogd/escape.c -o os_csyslogd/escape-rxu.o
	$(CC) $(CFLAGS) -I./os_csyslogd -I./external/cJSON -o $@ \
		tests/regressions/issue_rxuwsl9z_csyslog_escape.c \
		os_csyslogd/escape-rxu.o \
		-Wl,--start-group shared.a os_regex.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto

# ANT-2026-ZO60J6E9: authd.pass blank line must not disable password check.
issue_zo60j6e9_authd_pass: \
		tests/regressions/issue_zo60j6e9_authd_pass.c \
		os_auth/auth_pass.c shared.a
	$(CC) $(CFLAGS) -I./os_auth -c os_auth/auth_pass.c -o os_auth/auth_pass-zo60.o
	$(CC) $(CFLAGS) -I./os_auth -o $@ \
		tests/regressions/issue_zo60j6e9_authd_pass.c \
		os_auth/auth_pass-zo60.o \
		-Wl,--start-group shared.a os_regex.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto

# ANT-2026-5T5QGO1D: OS_AddNewAgent refuses at OS_ReadKeys fatal threshold.
# Small MAX_AGENTS keeps the fixture tiny; AUTH_FILE + wrap isChroot mimic authd.
issue_5t5qgo1d_authd_agent_limit: \
		tests/regressions/issue_5t5qgo1d_authd_agent_limit.c \
		addagent/validate.c shared.a os_crypto.a
	$(CC) $(CFLAGS) -DMAX_AGENTS=8 -DAUTH_FILE=\"client.keys\" \
		-c addagent/validate.c -o addagent/validate-5t5q.o
	$(CC) $(CFLAGS) -DMAX_AGENTS=8 -DAUTH_FILE=\"client.keys\" -o $@ \
		tests/regressions/issue_5t5qgo1d_authd_agent_limit.c \
		addagent/validate-5t5q.o \
		-Wl,--wrap=isChroot \
		-Wl,--start-group shared.a os_regex.a os_crypto.a os_net.a os_xml.a \
		os_zlib.a libcJSON.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto -lz

# ANT-2026-MYQZ0ORG: finish_event frees unless EF_LIST_RETAINED.
issue_myqz0org_ossec_alert_leak: \
		tests/regressions/issue_myqz0org_ossec_alert_leak.c \
		analysisd/eventinfo.c analysisd/eventinfo_list.c shared.a
	$(CC) $(CFLAGS) -I./analysisd -c analysisd/eventinfo.c \
		-o analysisd/eventinfo-myqz.o
	$(CC) $(CFLAGS) -I./analysisd -c analysisd/eventinfo_list.c \
		-o analysisd/eventinfo_list-myqz.o
	$(CC) $(CFLAGS) -I./analysisd -o $@ \
		tests/regressions/issue_myqz0org_ossec_alert_leak.c \
		analysisd/eventinfo-myqz.o analysisd/eventinfo_list-myqz.o \
		-Wl,--wrap=free \
		-Wl,--start-group shared.a os_regex.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto

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

# ANT-2026-739QMECR: ReadSecMSG uncompress limit must use remaining buffer room.
# Stubs BF/AES/zlib in the test; only msgs.o is needed from crypto.
issue_739qmecr_readsecmsg_uncompress: \
		tests/regressions/issue_739qmecr_readsecmsg_uncompress.c \
		os_crypto/shared/msgs.c
	$(CC) $(CFLAGS) -c os_crypto/shared/msgs.c -o os_crypto/shared/msgs-739q.o
	$(CC) $(CFLAGS) -o $@ tests/regressions/issue_739qmecr_readsecmsg_uncompress.c \
		os_crypto/shared/msgs-739q.o \
		-lpthread


# ANT-2026-2NLM3GPL: ReadSecMSG must not store crypto_method until auth.
# Stubs BF/AES/zlib in the test; only msgs.o is needed from crypto.
issue_2nlm3gpl_crypto_method_auth: \
		tests/regressions/issue_2nlm3gpl_crypto_method_auth.c \
		os_crypto/shared/msgs.c
	$(CC) $(CFLAGS) -c os_crypto/shared/msgs.c -o os_crypto/shared/msgs-2nlm.o
	$(CC) $(CFLAGS) -o $@ tests/regressions/issue_2nlm3gpl_crypto_method_auth.c \
		os_crypto/shared/msgs-2nlm.o \
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

# ANT-2026-2138NB95: report_changes snapshots must not follow symlinks.
issue_2138nb95_report_changes_symlink: \
		tests/regressions/issue_2138nb95_report_changes_symlink.c \
		syscheckd/seechanges.c shared.a os_crypto.a
	$(CC) $(CFLAGS) -DDEFAULTDIR=\".\" -I./syscheckd -o $@ \
		tests/regressions/issue_2138nb95_report_changes_symlink.c \
		syscheckd/seechanges.c \
		-Wl,--start-group shared.a os_crypto.a os_regex.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto

# ANT-2026-J8XF7LCX: whole-file reads stop at a byte cap.
issue_j8xf7lcx_file_max_size: \
		tests/regressions/issue_j8xf7lcx_file_max_size.c \
		syscheckd/seechanges.c syscheckd/fim_hash.c syscheckd/fim_dir.c shared.a os_crypto.a
	$(CC) $(CFLAGS) -DDEFAULTDIR=\".\" -I./syscheckd -o $@ \
		tests/regressions/issue_j8xf7lcx_file_max_size.c \
		syscheckd/seechanges.c syscheckd/fim_hash.c syscheckd/fim_dir.c \
		-Wl,--start-group shared.a os_crypto.a os_regex.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto

# ANT-2026-4T9F7XIQ: one snapshot per file, and a cap on the diff store.
issue_4t9f7xiq_diff_store: \
		tests/regressions/issue_4t9f7xiq_diff_store.c \
		syscheckd/seechanges.c shared.a os_crypto.a
	$(CC) $(CFLAGS) -DDEFAULTDIR=\".\" -I./syscheckd -o $@ \
		tests/regressions/issue_4t9f7xiq_diff_store.c \
		syscheckd/seechanges.c \
		-Wl,--start-group shared.a os_crypto.a os_regex.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread -lssl -lcrypto

# ANT-2026-MBH20U16: directory entries are looked up on the opened directory.
issue_mbh20u16_dirfd_walk: \
		tests/regressions/issue_mbh20u16_dirfd_walk.c \
		syscheckd/fim_dir.c
	$(CC) $(CFLAGS) -I./syscheckd -o $@ \
		tests/regressions/issue_mbh20u16_dirfd_walk.c \
		syscheckd/fim_dir.c \
		-Wl,--start-group shared.a os_regex.a -Wl,--end-group \
		-lpcre2-8 -lm -lpthread

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
		logcollector/read_audit.c logcollector/logr_fgets.c shared.a
	sed -e 's/^static void audit_send_msg/size_t audit_last_n;\nvoid audit_send_msg/' \
		-e 's/message\[n\] = '\''\\0'\'';/audit_last_n = n; message[n] = '\''\\0'\'';/' \
		logcollector/read_audit.c > logcollector/read_audit-ud31vlyl.c
	$(CC) $(CFLAGS) -I./logcollector -c logcollector/read_audit-ud31vlyl.c \
		-o logcollector/read_audit-ud31vlyl.o
	$(CC) $(CFLAGS) -I./logcollector -o $@ \
		tests/regressions/issue_ud31vlyl_audit_oob.c \
		logcollector/read_audit-ud31vlyl.o logcollector/logr_fgets.c \
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
multiline_underflow: tests/regressions/multiline_underflow.c logcollector/read_multiline.c \
		logcollector/logr_fgets.c
	$(CC) $(CFLAGS) -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -fno-builtin-strncpy \
		-I./logcollector -c logcollector/read_multiline.c -o logcollector/read_multiline-underflow.o
	$(CC) $(CFLAGS) -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 \
		-I./logcollector -c logcollector/logr_fgets.c -o logcollector/logr_fgets-underflow.o
	$(CC) $(CFLAGS) -I./logcollector -o $@ tests/regressions/multiline_underflow.c \
		logcollector/read_multiline-underflow.o logcollector/logr_fgets-underflow.o

addagent/validate.o: addagent/validate.c
	$(CC) $(CFLAGS) -c addagent/validate.c -o $@

clean:
	rm -f $(REGRESSION_BINS) config-pund.a \
		os_execd/timeout_dup-snx.o \
		os_execd/timeout_dup-2lg.o \
		os_dbd/alert-sint.o os_dbd/db_op-sint.o \
		os_csyslogd/escape-rxu.o \
		os_csyslogd/escape-grfz.o \
		os_auth/auth_pass-zo60.o \
		addagent/validate-5t5q.o \
		analysisd/eventinfo-myqz.o analysisd/eventinfo_list-myqz.o \
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
		analysisd/decoders/syscheck-tzmh.o \
		analysisd/cleanevent-j9qh.o \
		analysisd/decoders/syscheck-rbaky.o \
		analysisd/decoders/rootcheck-rbaky.o \
		analysisd/fts-4ojp.o \
		analysisd/fts-mqq5.o \
		os_csyslogd/alert-grfz.o \
		os_csyslogd/json-queue-dj9.o
