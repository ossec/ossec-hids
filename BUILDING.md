# Building OSSEC HIDS

See [INSTALL](INSTALL) for dependencies and `install.sh` usage.

## Configuration reload (`ossec-control reload`)

`ossec-control reload` sends **SIGHUP** to running daemons. Processes keep the same PID where reload is supported. **Reload requires the same trust level as editing `ossec.conf` as root** (or equivalent control of the install).

| Daemon | Reload behavior | Requires `restart` |
|--------|-----------------|-------------------|
| ossec-analysisd | Atomic staging reload: rules, decoders, lists, and global config swap only after successful validation. Active-response XML is parsed into staging lists before commit. Failed **staging** reload keeps the previous configuration. Failed reload **after** commit (AR file write, FTS, accumulator) leaves a **partial** state — restart analysisd. Orphans previous rule/decoder trees on success (RSS may grow; see limits below). | After post-commit partial reload, repeated failed reload, or when `max_config_reloads` is exceeded |
| ossec-logcollector | `localfile` and logreader set (load-then-swap) | — |
| ossec-remoted | Non-bind `<remote>` settings under `send_msg_lock` | **Bind address/port/protocol/IPv6 changes** (per-listener `ipv6` and `proto` compared by `conn[]` listener count, not zero-terminated) |
| ossec-syscheckd | FIM directories and options (restarts watches) | — |
| ossec-maild | Email/SMTP settings | — |
| ossec-execd | Active-response disabled flag, repeated offenders | **Active-response command changes** when analysisd cannot rewrite `etc/shared/ar.conf` (typical post-chroot `ossec` user) |
| ossec-monitord | Report schedules and filters | **SMTP server DNS change** (after chroot) |
| ossec-csyslogd | Syslog forwarding targets | — |
| ossec-dbd | Database connection settings | — |
| ossec-agentlessd | Agentless entries | — |
| ossec-authd | Password file and TLS context when no worker children are active (pending reload retries when busy) | **Listen port** (CLI at start) |
| ossec-agentd | Client config load-then-swap; server IP reconnect only if `<allow-reload-reconnect>yes</allow-reload-reconnect>` | Server IP change without that flag |

### analysisd reload limits

- **`max_config_reloads`** (internal option in `etc/internal_options.conf`, default **10** if missing): after this many **successful** reloads per process lifetime, further reloads are refused until `ossec-analysisd` is restarted. A missing define does not terminate analysisd.
- **Staging abort:** if rules/decoders/AR XML fail validation, live rules and AR are unchanged; logs say *using previous configuration*. Decoder parse errors during reload return to the caller instead of terminating analysisd.
- **Post-commit failure:** if rules/decoders already swapped but AR commit, FTS, or accumulator reinit fails, logs say *partial reload* / *restart recommended* — do not assume the old ruleset is still active. If only **AR commit** fails after the rules swap, the **previous in-memory AR lists** remain and `ar_flag` / `Config.ar` are restored to the pre-reload values (new rules may still reference different AR XML until restart).
- **FTS/accumulator failure** after commit: new rules are live; restart `ossec-analysisd`.
- Orphaned rule/decoder memory from successful reloads is not freed immediately (avoids use-after-free); plan for periodic analysisd restart in environments that reload often.

### Active response (analysisd vs execd)

- On **startup as root**, analysisd writes `etc/shared/ar.conf` and execd uses it.
- On **reload as root** (before chroot or as root helper), analysisd parses AR into staging lists first (no `ar.conf` writes during parse), then atomically installs `etc/shared/ar.conf` via a temp file and `rename` from the committed lists after a successful parse; a failed install leaves the previous `ar.conf` on disk. `ossec-execd` receives SIGHUP with other daemons and reloads its XML flags.
- On **reload as `ossec`** (after chroot), analysisd updates in-memory AR only (no `ar.conf` rewrite); entries are logged to `var/run/ar_reload_sink` (capped at 1 MiB). analysisd logs that execd may need a restart. **Restart `ossec-execd`** (or full restart) if AR **commands** in XML change — execd may still be using a stale `ar.conf`.

### Agent server address

Default: changing `<server-ip>` / `<server-hostname>` on reload does **not** reconnect. Set `<allow-reload-reconnect>yes</allow-reload-reconnect>` in the client `<client>` block to allow reconnect on reload. When reconnect is allowed, the agent reconnects if `<port>` is unset, a **port is added** where none was set before, the **port value changes**, the previous server address is **missing** from the new list, or a server list appears where none was configured before; the slot is resolved by **address match** in the new list, not the pre-reload index.

### Control script

- Reload signals a **single** PID per daemon (ambiguous PID files are skipped).
- Minimum interval between reloads: **5 seconds** (override with `OSSEC_RELOAD_MIN_INTERVAL`).

Use `ossec-control restart` when:

- `ossec-remoted` listen socket settings change
- `ossec-monitord` SMTP server hostname changes (post-install chroot)
- `ossec-authd` port or certificate paths change (started via CLI flags)
- Active-response commands change and analysisd runs non-root after chroot
- Any daemon logs reload failure / `restart required`

## Quick build (server)

```bash
cd src
make clean
make TARGET=server
```

## Reload regression tests

```bash
./contrib/test-reload.sh
# Optional: TEST_RELOAD_STRESS=1 ./contrib/test-reload.sh
# Optional: TEST_RELOAD_LEAK=1 ./contrib/test-reload.sh   # RSS after 10 failed reloads
# Optional: TEST_RELOAD_VERIFY_RULES=1 ./contrib/test-reload.sh  # logger + rule 1999998
# Optional: TEST_RELOAD_AGENT=1 ./contrib/test-reload.sh  # agentd PID stable after reload
```

The default script run includes bad-rules and bad-`local_decoder.xml` staging-abort checks (analysisd must stay up).

Requires a running install under `/var/ossec` (or set `OSSEC_DIR` / first argument).
