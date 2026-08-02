# Analysisd / pipeline regression tests
#
# From `src/` after building the server target:
#
#   make TARGET=server -j$(nproc)
#   make regression
#
# Or directly:
#
#   make -f tests/regressions/Makefile
#   make -f tests/regressions/Makefile check
#
# Shared queue/thread unit tests (automated):
#
#   make -C shared/tests check
#
# Interactive helpers (prime/hash/merge/ip) are optional:
#   make -C shared/tests legacy_helpers
#
# Covered binaries (make check):
#   - issue_1079_last_events_uaf       frequency last_events ownership
#   - issue_correlation_agent_shard    location EventList isolation +
#                                      if_matched_sid cross-location
#   - issue_1748_sid_list_crash        sid_prev_matched overflow + free callback
#   - issue_1274_auth_ipv6_key         auth IPv6 key handling
#
# Additional scripts without unified Make targets (manual / historical):
#   issue_1814_control_chars.c, issue_1817_uaf_fix.c, issue_1818_syscheck_uaf.c,
#   issue_1953_xml_recursion.c, issue_2056_repro_crash.c
#
# Notes for new tests:
#   - Define TLS time globals with `__thread` (`c_time`, `__crt_hour`, `__crt_wday`)
#     so they link against analysisd objects that use thread-local clock state.
#   - Call `os_mutex_init(&rule->mutex, NULL)` on any RuleInfo used with Search_*.
#   - Do not stub `OS_GetLastEvent` when linking `eventinfo_list-live.o`.
#
# Correlation / shard semantics (pipeline rule_matching_threads > 1):
#   - EventList history used by Search_LastEvents is **per location-hashed shard**.
#   - Frequency/context that must span multiple agents should use if_matched_sid
#     or if_matched_group (those lists remain global under rule->mutex).
#   - Migration checklist: inventory multi-agent frequency rules → convert to
#     if_matched_sid/group → keep pure Search_LastEvents only for local correlation.
#   - Ops: events_received, events_dropped*, alerts_dropped*, archives_dropped*,
#     raw_input_queue_*, fts_queue_*, and *_delta fields in ossec-analysisd.state.
#     Raise queue sizes, lower EPS, or tune analysisd.*_push_wait_ms /
#     input_demux_threads / raw_input_queue_size — no sync fallback for mid-pipe
#     drops (alerts still sync-fall back).
#   - Rate-limited merror WARN "pipeline queue pressure" also fires under drop load.
#
# Soak SLO / Nested replacement checklist (rule_matching_threads >= 2):
#   1. Build/install ossec-analysisd; refresh etc/internal_options.conf knobs.
#   2. ossec-control stop; kill leftover ossec-analysisd PIDs; confirm none remain.
#   3. ossec-control start; confirm exactly one analysisd PID and pipeline log line
#      (input_demux, shards); expect shard correlation reminder when shards > 1.
#   4. .state: events_received increasing; statistical/raw/fts queue_* present;
#      events_dropped_delta and events_dropped_shard_delta ~0 after settle;
#      alerts flowing; Check_Hour uses statistical writer when stats enabled.
#   5. Short burst should be absorbed by raw/demux wait_ms without sustained
#      mid-pipe deltas; sustained overload may increment drops (expected).
#
# Wave 4 product planes (SCA/syscollector/winevt/dbsync/upgrade): deferred until
# Waves 1–3 soak SLOs hold and product names a cutover plane.
