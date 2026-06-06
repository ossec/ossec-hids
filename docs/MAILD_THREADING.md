# ossec-maild threading model

This document describes the threaded mail/SMS send path introduced in the OSSEC 4.1
fork-to-threads migration (`maild`, `mail_list`, `sendmail` / `curlmail`).

## Architecture

- The **main loop** in `maild.c` reads alerts from the mail queue, updates grouped
  subject / granular routing state, and spawns **detached worker threads** for SMTP.
- Each batch send **snapshots** `_g_subject`, `gran_set`, and the mail list under
  `mail_send_mu` then `mail_list_mu` (always in that order), **drains** the list into
  a `MailNode` chain, and passes ownership to `mail_send_worker`.
- Workers call `OS_Sendmail` or `OS_Sendsms` with the snapshot only; they must not
  read live `gran_set` / `_g_subject` after spawn.
- On successful `CreateThread`, the main loop **commits** by clearing live
  `_g_subject` and `gran_set` flags.

## Lock ordering

1. `mail_send_mu` — grouped subject and live `gran_set`
2. `mail_list_mu` — mail list structure (`OS_MailListLock` / `OS_MailListUnlock`)

Never acquire `mail_list_mu` while holding `mail_workers_mu`.

## Limits (`internal_options.conf`)

| Option | Meaning |
|--------|---------|
| `maild.max_workers` | Max concurrent send workers (default 1, max 32). |
| `email_maxperhour` | Max **worker spawns** per hour (email + SMS), not SMTP completions. With `max_workers > 1`, concurrent SMTP sessions are capped separately by `max_workers`. |
| `MAIL_LIST_SIZE` (96) | Max queued mail nodes before oldest are dropped. |

SMS deferred when the hourly cap or `max_workers` is reached is logged at verbose level
once per hour.

## SMTP builds

- **TCP** (`sendmail.c`): plain SMTP or local sendmail pipe (`smtp_server` path starting with `/`).
- **libcurl** (`USE_SMTP_CURL`, `curlmail.c`): TLS/AUTH; requires network `smtp_server` (not a pipe).

Both paths reject CR/LF in recipient addresses (`mail_address_has_crlf`) and strip CR/LF
from header values (`mail_sanitize_header_value` in `mail_utils.c`).

## Graceful shutdown

On `SIGINT` / `SIGTERM` / `SIGQUIT`, the first signal sets `maild_shutting_down`:

- No new SMS or batch workers are started.
- The main loop waits until `mail_active_workers == 0` (poll every 1s).
- If workers do not finish within **60 seconds**, maild logs a warning and exits.
- A second signal forces immediate exit (legacy behavior).

## CreateThread failure

If spawning a worker fails after draining the batch, `OS_RequeueMailBatch` restores the
list (newest-first live order). Backoff is exponential (1, 2, 4, … up to 30s) instead of
a fixed 30s sleep.

## Staging test matrix

Run on a test manager with mail alerts enabled. Record pass/fail.

| # | Scenario | Steps | Expected |
|---|----------|-------|----------|
| 1 | Requeue on spawn failure | Temporarily lower `maild.max_workers` to 0 or use `ulimit` to block threads; trigger grouped mail | Batch reappears in queue; order preserved after retry |
| 2 | Granular email | Two `granular` recipients, different levels | Correct RCPT per `FULL_FORMAT` / override snapshot |
| 3 | SMS | `sms` + granular SMS recipient | SMS worker sends; defer log if hourly cap hit |
| 4 | `strict_checking` | SMTP server that rejects bad DATA | TCP path logs END_DATA error when enabled |
| 5 | Hourly cap | `email_maxperhour=1`, many alerts in one hour | Second spawn deferred until next hour |
| 6 | CRLF recipient (TCP) | Misconfigured `email_to` with embedded `\r\n` | Recipient skipped; warn once; no extra SMTP commands |
| 7 | Shutdown | `kill -TERM` maild during active send | No new spawns; exit within 60s or timeout warn |

## Requeue unit test

From `src/os_maild/tests`:

```bash
make mail_list_requeue_test
./mail_list_requeue_test
```

Validates drain → `OS_RequeueMailBatch` → drain preserves oldest-first order.
