# Review: PR #1360 – Allow TLS Email sends as a compile-time option

**PR:** https://github.com/ossec/ossec-hids/pull/1360  
**Author:** @alexbartlow  
**Branch:** `secure_mail_with_curl` → `ossec:master`  
**Summary:** Adds a compile-time option `SENDMAIL_CURL=1` so ossec-maild can send email via **curl** with TLS and SMTP auth to an external SMTP server, instead of plain TCP or a local sendmail proxy.

---

## What the PR does

- **New file** `src/os_maild/curlmail.c`: when `SENDMAIL_CURL` is defined, implements `OS_Sendmail()` using libcurl (SMTP with optional auth and SSL).
- **Config:** Adds `auth_smtp`, `smtp_user`, `smtp_password`, `secure_smtp` to global/mail config and XML parsing.
- **Build:** Makefile adds `-DSENDMAIL_CURL=1` and `-lcurl` when `SENDMAIL_CURL=yes`.
- **Existing path:** When `SENDMAIL_CURL` is not set, existing `sendmail.c` (plain TCP or local sendmail) is unchanged.
- **Installer:** install.sh gains interactive prompts for SMTP auth and secure SMTP and writes them into ossec.conf.

---

## Critical issues (must fix before merge)

### 1. **install.sh: copies entire system `/lib` (first commit)**

```sh
mkdir ${INSTALLDIR}/lib
cp -R /lib/* ${INSTALLDIR}/lib
```

This copies the **whole system** `/lib` into the OSSEC install directory. That is wrong and dangerous (huge, architecture-specific, can break the system). It looks like a mistake (e.g. intended to copy only libcurl or a small set of libs for a relocatable install). This block should be **removed** or replaced with a minimal, documented copy (e.g. only libcurl and its deps) if a bundled libcurl is really required.

### 2. **curlmail.c: `strftime` into NULL**

```c
char *messageId = NULL;
// ...
strftime(messageId, 127, "%a%d%b%Y%T%z", p);
sprintf(payload_text[3], "Message-ID: <%s@%s> \r\n", messageId, hostname);
```

`messageId` is never assigned; writing with `strftime(messageId, 127, ...)` is undefined behavior (and will crash). Use a buffer, e.g.:

```c
char messageId[128];
strftime(messageId, sizeof(messageId), "%a%d%b%Y%T%z", p);
```

### 3. **Auth when not configured**

In `config.c` the PR sets `Mail->authsmtp = -1` when unset. In curlmail.c, `if(mail->authsmtp)` is used. So with default config, `authsmtp` is -1 (truthy) and the code can try to use auth with `smtp_user`/`smtp_pass` still NULL. Either initialize `authsmtp` to 0 when not set, or check `if(mail->authsmtp == 1)` (and similarly for `securesmtp` if needed).

---

## Other issues (should fix or discuss)

### 4. **Only one recipient**

Current sendmail.c supports multiple recipients (`mail->to[]`, `mail->gran_to[]`). In curlmail.c only the first is used:

```c
recipients = curl_slist_append(recipients, mail->to[0]);
```

So with the curl path, additional recipients (CCs, granular recipients) are not used. Either document this limitation or add a loop over `mail->to[]` (and granular recipients if desired) and append each to `recipients`.

### 5. **Verbose curl in production**

`curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);` sends curl debug output to stderr. That can be noisy and may leak sensitive data (e.g. server names). Prefer disabling by default or gating on a debug flag.

### 6. **Hardcoded CA bundle**

`curl_easy_setopt(curl, CURLOPT_CAINFO, "/etc/ssl/certs/cacert.pem");` is Linux-specific. FreeBSD and others use different paths. Better to leave CAINFO unset (use curl’s default) or make it configurable.

### 7. **SMTP URL and port**

Config stores `smtpserver` as hostname (or URL?). For curl, the URL must be e.g. `smtp://host` or `smtps://host:465`. If the existing config only stores a hostname, the code should prepend `smtps://` or `smtp://` and append `:465` (or configured port) when building the URL. Confirm expected config format and document or adjust.

### 8. **Passwords in plain text in ossec.conf**

The installer writes `smtp_password` into the config file in plain text. That’s consistent with other secrets in ossec.conf but should be called out in docs (file permissions, risk of exposure). No code change strictly required, but consider a short security note.

### 9. **Static `payload_text` and small leak**

`payload_text[0]`..`[4]` are malloc’d once and never freed. One-time leak; if the process is long-lived it’s minor. Cleaner to use stack buffers or free before returning.

---

## Positive points

- **Compile-time switch:** Keeps existing behavior default; curl path is opt-in.
- **Review fix:** Second commit correctly removes the hardcoded DNS server list (per @nbuuck’s review).
- **Config and parsing:** Auth and secure SMTP are wired through global and mail config in a coherent way.
- **Use case:** Direct TLS + auth to an external SMTP server is a real need and avoids a local sendmail proxy.

---

## Recommendation

- **Do not merge as-is** because of (1) install.sh `/lib` copy and (2) `strftime` into NULL.
- After fixing the critical items and addressing (3), the feature is in good shape to merge. Addressing (4)–(9) would make the curl path more robust and portable.
- If the project prefers not to depend on libcurl or to keep mail code minimal, the alternative mentioned in the PR (e.g. a thinner implementation with libsodium or similar) could be considered later; for many deployments, curl is acceptable and well understood.

---

## References

- PR: https://github.com/ossec/ossec-hids/pull/1360  
- Existing mail path: `src/os_maild/sendmail.c` (plain TCP port 25 or local sendmail).  
- Config: `src/config/mail-config.h` (no auth fields today); PR adds `authsmtp`, `smtp_user`, `smtp_pass`, `securesmtp`.
