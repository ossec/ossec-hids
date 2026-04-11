# General Code Audit: SMTP AUTH/TLS (libcurl) Changes

**Scope:** All changes for the SMTP authentication and TLS feature (USE_SMTP_CURL / USE_CURL build option).  
**Files:** `src/os_maild/curlmail.c`, `src/os_maild/maild.c`, `src/os_maild/sendmail.c`, `src/os_maild/config.c`, `src/config/global-config.c`, `src/config/global-config.h`, `src/config/mail-config.h`, `src/monitord/main.c`.

---

## 1. Summary

The implementation adds optional SMTP TLS and authentication via libcurl, gated by `USE_SMTP_CURL`. Security measures include header/envelope sanitization, hostname validation, explicit TLS verification, credential clearing, and pre-resolving the SMTP host for chroot. The following items were audited and, where needed, fixed or documented.

---

## 2. curlmail.c

| Area | Finding | Severity | Status |
|------|---------|----------|--------|
| **Header/recipient injection** | `sanitize_header_value()` strips CR/LF from Subject/From/To; recipients with CR/LF are skipped and logged. | — | OK |
| **Hostname validation** | `is_valid_smtp_host()` restricts to alphanumeric, hyphen, dot; length ≤ 253. | — | OK |
| **Payload callback** | `payload_source()` checks `nmemb * size` for overflow before use. | — | OK |
| **URL / resolve buffers** | `snprintf` return checked for truncation (url, resolve_buf, header_buf). | — | OK |
| **Recipient list** | `curl_slist_append` failure for recipients or resolve list handled; list freed in `done`. | — | OK |
| **TLS** | `CURLOPT_SSL_VERIFYPEER=1`, `CURLOPT_SSL_VERIFYHOST=2`; `CURLOPT_USE_SSL=CURLUSESSL_ALL` when auth or secure_smtp. | — | OK |
| **Timeouts** | `CURLOPT_CONNECTTIMEOUT`, `CURLOPT_TIMEOUT` set. | — | OK |
| **Signals** | `CURLOPT_NOSIGNAL=1` set to avoid libcurl using `alarm()`. | — | OK |
| **Local sendmail** | Rejected with clear error when `smtpserver` is a path. | — | OK |
| **Global init/cleanup** | No longer in `OS_Sendmail()`; init in `maild.c` main, cleanup in atexit (see maild.c). | — | OK |

**Minor:** `verbose()` for unencrypted SMTP uses port that may be defaulted in the block above (e.g. 25); logic is consistent.

---

## 3. maild.c

| Area | Finding | Severity | Status |
|------|---------|----------|--------|
| **curl_global_init** | Called once in `main()` after MailConf and atexit registration; fails with ErrorExit. | — | OK |
| **curl_global_cleanup** | Must run on process exit. | Medium | **Fixed:** Added `curl_global_cleanup()` at end of `maild_clear_smtp_secrets()` atexit handler. |
| **Pre-resolve** | USE_SMTP_CURL block pre-resolves hostname before chroot if `smtpserver_resolved` not set; ErrorExit on failure. | — | OK |
| **Chroot condition** | `mail.smtpserver[0]` was used without NULL check. | Medium | **Fixed:** Condition changed to `if (mail.smtpserver && mail.smtpserver[0] != '/')` to avoid NULL dereference when `smtp_server` is missing in config. |
| **Child credentials** | In forked child, `smtp_user` and `smtp_pass` cleared with `memset_secure` before `exit(0)`. | — | OK |
| **atexit** | `maild_clear_smtp_secrets` clears smtp_user, smtp_pass, smtpserver_resolved; then calls `curl_global_cleanup()`. | — | OK |

---

## 4. global-config.c

| Area | Finding | Severity | Status |
|------|---------|----------|--------|
| **Credential order** | `smtp_user` and `smtp_password` stored regardless of `auth_smtp` order; password cleared with `memset_secure` before free. | — | OK |
| **smtpserver (USE_SMTP_CURL)** | Hostname path: `OS_GetHost()` for `smtpserver_resolved`; config load fails on resolution failure; hostname stored in `smtpserver`; single `free` + `os_strdup` for `smtpserver`. | — | OK |
| **smtp_port** | Parsed and validated 1–65535; `OS_StrIsNum` used. | — | OK |
| **auth_smtp / secure_smtp** | Only "yes"/"no" accepted; invalid value returns OS_INVALID. | — | OK |

---

## 5. config.c (os_maild)

| Area | Finding | Severity | Status |
|------|---------|----------|--------|
| **Non-CURL build** | Rejects auth_smtp, secure_smtp, smtp_port, smtp_user, smtp_pass with clear message. | — | OK |
| **CURL build** | When auth_smtp=1, requires both smtp_user and smtp_password. | — | OK |
| **Initialization** | All new Mail fields (smtpserver_resolved, authsmtp, securesmtp, smtp_port, smtp_user, smtp_pass) initialized. | — | OK |

---

## 6. monitord/main.c

| Area | Finding | Severity | Status |
|------|---------|----------|--------|
| **USE_SMTP_CURL** | For hostname (non-path) smtp_server, validates with `OS_GetHost()`; on success frees resolved IP and stores hostname in `mond.smtpserver`; on failure sets `mond.smtpserver = NULL` so existing error path disables reports. | — | OK |
| **tmpsmtp leak** | `free(tmpsmtp)` and null set on success path. | — | OK |

---

## 7. sendmail.c (non-CURL path)

| Area | Finding | Severity | Status |
|------|---------|----------|--------|
| **Guard** | Entire implementation under `#ifndef USE_SMTP_CURL`. | — | OK |
| **Consistency** | Original sendmail path unchanged; still uses `mail->smtpserver[0]` (assumes config guarantees smtp_server when mail enabled; maild.c now guards chroot for NULL). | Low | No change; non-CURL path behavior unchanged. |

---

## 8. Headers and types

| Area | Finding | Severity | Status |
|------|---------|----------|--------|
| **mail-config.h** | New fields documented; `smtpserver_resolved` comment references CURLOPT_RESOLVE and chroot. | — | OK |
| **global-config.h** | `authsmtp` and `securesmtp` in Config. | — | OK |

---

## 9. Fixes applied during audit

1. **maild.c – atexit:** Added `curl_global_cleanup()` at the end of `maild_clear_smtp_secrets()` so curl global state is torn down on exit (parent and forked children), matching the design of initializing curl once in main.
2. **maild.c – chroot:** Guarded chroot with `mail.smtpserver && mail.smtpserver[0] != '/'` to avoid NULL dereference when `smtp_server` is missing in config.

---

## 10. Recommendations

- **CA bundle in chroot:** Document (e.g. in install or admin docs) that TLS verification requires a CA bundle inside the chroot (e.g. copy or symlink into `<chroot>/etc/ssl/certs/`) when using remote SMTP with TLS. Already noted in commit message / foo1.txt.
- **Optional hardening:** In `config.c` (MailConf), consider requiring `smtpserver` when `mn` is set, so the process fails fast at config load instead of later in maild when sending; current behavior is still safe due to the NULL check and OS_Sendmail checks.
- **Tests:** Run testsuite with `USE_CURL=yes` and a test config that uses auth_smtp/secure_smtp to confirm end-to-end behavior.

---

*Audit completed; two fixes applied in maild.c.*
