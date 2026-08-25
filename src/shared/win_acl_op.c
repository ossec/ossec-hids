/* Copyright (C) 2026 Atomicorp, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "shared.h"
#include "win_acl_op.h"
#include "os_crypto/md5/md5_op.h"

#ifdef WIN32
#include <aclapi.h>
#include <sddl.h>
#endif

/* Access mask bits (Windows values). */
#define FIM_MASK_GENERIC_READ     0x80000000
#define FIM_MASK_GENERIC_WRITE    0x40000000
#define FIM_MASK_GENERIC_EXECUTE  0x20000000
#define FIM_MASK_GENERIC_ALL      0x10000000
#define FIM_MASK_DELETE           0x00010000
#define FIM_MASK_READ_CONTROL     0x00020000
#define FIM_MASK_WRITE_DAC        0x00040000
#define FIM_MASK_WRITE_OWNER      0x00080000
#define FIM_MASK_SYNCHRONIZE      0x00100000
#define FIM_MASK_FILE_READ_DATA   0x00000001
#define FIM_MASK_FILE_WRITE_DATA  0x00000002
#define FIM_MASK_FILE_APPEND_DATA 0x00000004
#define FIM_MASK_FILE_READ_EA     0x00000008
#define FIM_MASK_FILE_WRITE_EA    0x00000010
#define FIM_MASK_FILE_EXECUTE     0x00000020
#define FIM_MASK_FILE_READ_ATTR   0x00000080
#define FIM_MASK_FILE_WRITE_ATTR  0x00000100

void fim_acl_free(fim_acl_t *acl)
{
    if (!acl) {
        return;
    }
    free(acl->aces);
    acl->aces = NULL;
    acl->count = 0;
    acl->special = FIM_ACL_NORMAL;
}

static int ace_cmp(const void *a, const void *b)
{
    const fim_ace_t *xa = a;
    const fim_ace_t *xb = b;
    int c;

    /* Preserve evaluation order: primary key is original DACL index. */
    if (xa->ord != xb->ord) {
        return (xa->ord < xb->ord ? -1 : 1);
    }
    c = strcmp(xa->sid, xb->sid);
    if (c != 0) {
        return (c);
    }
    if (xa->type != xb->type) {
        return (xa->type < xb->type ? -1 : 1);
    }
    if (xa->flags != xb->flags) {
        return (xa->flags < xb->flags ? -1 : 1);
    }
    if (xa->mask != xb->mask) {
        return (xa->mask < xb->mask ? -1 : 1);
    }
    return (0);
}

void fim_acl_sort(fim_acl_t *acl)
{
    if (!acl || !acl->aces || acl->count < 2) {
        return;
    }
    qsort(acl->aces, acl->count, sizeof(fim_ace_t), ace_cmp);
}

static void append_str(char *buf, size_t buflen, size_t *used, const char *s)
{
    size_t n;

    if (!buf || !used || !s || buflen == 0) {
        return;
    }
    n = strlen(s);
    if (*used >= buflen) {
        return;
    }
    if (*used + n >= buflen) {
        n = buflen - *used - 1;
    }
    memcpy(buf + *used, s, n);
    *used += n;
    buf[*used] = '\0';
}

static void format_inherit(unsigned int flags, char *out, size_t outlen)
{
    char tmp[32];
    size_t u = 0;

    tmp[0] = '\0';
    if (flags & FIM_ACE_OI) {
        append_str(tmp, sizeof(tmp), &u, "OI");
    }
    if (flags & FIM_ACE_CI) {
        if (u) {
            append_str(tmp, sizeof(tmp), &u, ",");
        }
        append_str(tmp, sizeof(tmp), &u, "CI");
    }
    if (flags & FIM_ACE_IO) {
        if (u) {
            append_str(tmp, sizeof(tmp), &u, ",");
        }
        append_str(tmp, sizeof(tmp), &u, "IO");
    }
    if (flags & FIM_ACE_NP) {
        if (u) {
            append_str(tmp, sizeof(tmp), &u, ",");
        }
        append_str(tmp, sizeof(tmp), &u, "NP");
    }
    if (flags & FIM_ACE_ID) {
        if (u) {
            append_str(tmp, sizeof(tmp), &u, ",");
        }
        append_str(tmp, sizeof(tmp), &u, "ID");
    }
    if (u == 0) {
        snprintf(out, outlen, "-");
    } else {
        snprintf(out, outlen, "%s", tmp);
    }
}

static void format_mask(unsigned int mask, char *out, size_t outlen)
{
    static const struct {
        unsigned int bit;
        const char *name;
    } bits[] = {
        { FIM_MASK_GENERIC_READ,     "GENERIC_READ" },
        { FIM_MASK_GENERIC_WRITE,    "GENERIC_WRITE" },
        { FIM_MASK_GENERIC_EXECUTE,  "GENERIC_EXECUTE" },
        { FIM_MASK_GENERIC_ALL,      "GENERIC_ALL" },
        { FIM_MASK_DELETE,           "DELETE" },
        { FIM_MASK_READ_CONTROL,     "READ_CONTROL" },
        { FIM_MASK_WRITE_DAC,        "WRITE_DAC" },
        { FIM_MASK_WRITE_OWNER,      "WRITE_OWNER" },
        { FIM_MASK_SYNCHRONIZE,      "SYNCHRONIZE" },
        { FIM_MASK_FILE_READ_DATA,   "FILE_READ_DATA" },
        { FIM_MASK_FILE_WRITE_DATA,  "FILE_WRITE_DATA" },
        { FIM_MASK_FILE_APPEND_DATA, "FILE_APPEND_DATA" },
        { FIM_MASK_FILE_READ_EA,     "FILE_READ_EA" },
        { FIM_MASK_FILE_WRITE_EA,    "FILE_WRITE_EA" },
        { FIM_MASK_FILE_EXECUTE,     "FILE_EXECUTE" },
        { FIM_MASK_FILE_READ_ATTR,   "FILE_READ_ATTRIBUTES" },
        { FIM_MASK_FILE_WRITE_ATTR,  "FILE_WRITE_ATTRIBUTES" },
        { 0, NULL }
    };
    size_t used = 0;
    int i;
    int any = 0;
    unsigned int residual = mask;

    out[0] = '\0';
    for (i = 0; bits[i].name; i++) {
        if ((mask & bits[i].bit) == 0) {
            continue;
        }
        if (any) {
            append_str(out, outlen, &used, ", ");
        }
        append_str(out, outlen, &used, bits[i].name);
        residual &= ~bits[i].bit;
        any = 1;
    }
    if (any && residual) {
        char extra[24];
        snprintf(extra, sizeof(extra), "0x%08x", residual);
        append_str(out, outlen, &used, ", ");
        append_str(out, outlen, &used, extra);
    }
    if (!any) {
        snprintf(out, outlen, "0x%08x", mask);
    }
}

#ifdef WIN32
static void sid_to_name(const char *sid_str, char *name, size_t namelen)
{
    PSID sid = NULL;
    char account[256];
    char domain[256];
    DWORD acc_sz = sizeof(account);
    DWORD dom_sz = sizeof(domain);
    SID_NAME_USE use;

    name[0] = '\0';
    if (!ConvertStringSidToSidA(sid_str, &sid) || !sid) {
        snprintf(name, namelen, "%s", sid_str);
        return;
    }
    if (LookupAccountSidA(NULL, sid, account, &acc_sz, domain, &dom_sz, &use)) {
        if (domain[0]) {
            snprintf(name, namelen, "%s\\%s", domain, account);
        } else {
            snprintf(name, namelen, "%s", account);
        }
    } else {
        snprintf(name, namelen, "%s", sid_str);
    }
    LocalFree(sid);
}
#else
static void sid_to_name(const char *sid_str, char *name, size_t namelen)
{
    snprintf(name, namelen, "%s", sid_str);
}
#endif

int fim_win_acl_snapshot(const fim_acl_t *acl, char *buf, size_t buflen)
{
    size_t used = 0;
    size_t i;
    char line[512];

    if (!acl || !buf || buflen == 0) {
        return (-1);
    }
    buf[0] = '\0';

    if (acl->special == FIM_ACL_NODACL) {
        append_str(buf, buflen, &used, "SPECIAL=NODACL\n");
        return (0);
    }
    if (acl->special == FIM_ACL_NULLDACL) {
        append_str(buf, buflen, &used, "SPECIAL=NULLDACL\n");
        return (0);
    }

    for (i = 0; i < acl->count; i++) {
        const fim_ace_t *a = &acl->aces[i];
        int len;

        len = snprintf(line, sizeof(line), "%u|%s|%d|%u|%u\n",
                       a->ord, a->sid, a->type, a->flags, a->mask);
        if (len < 0) {
            continue;
        }
        if (used + (size_t)len + sizeof("... truncated ...\n") >= buflen) {
            append_str(buf, buflen, &used, "... truncated ...\n");
            break;
        }
        append_str(buf, buflen, &used, line);
    }
    return (0);
}

char *fim_win_acl_snapshot_dup(const fim_acl_t *acl)
{
    char *snap = NULL;
    size_t cap = 8192;
    const size_t max_cap = 256 * 1024;

    if (!acl) {
        return (NULL);
    }

    for (;;) {
        char *neu = realloc(snap, cap);
        if (!neu) {
            free(snap);
            return (NULL);
        }
        snap = neu;
        if (fim_win_acl_snapshot(acl, snap, cap) != 0) {
            free(snap);
            return (NULL);
        }
        if (strstr(snap, "... truncated") == NULL) {
            return (snap);
        }
        if (cap >= max_cap) {
            free(snap);
            return (NULL);
        }
        cap *= 2;
    }
}

int fim_win_acl_parse_snapshot(const char *text, fim_acl_t *out)
{
    char *copy;
    char *line;
    char *save = NULL;
    size_t cap = 16;
    size_t n = 0;

    if (!text || !out) {
        return (-1);
    }
    memset(out, 0, sizeof(*out));
    os_strdup(text, copy);
    out->aces = calloc(cap, sizeof(fim_ace_t));
    if (!out->aces) {
        free(copy);
        return (-1);
    }

    for (line = strtok_r(copy, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        fim_ace_t ace;
        char sid[192];
        int type;
        unsigned int flags, mask, ord;

        if (strncmp(line, "SPECIAL=NODACL", 14) == 0) {
            out->special = FIM_ACL_NODACL;
            break;
        }
        if (strncmp(line, "SPECIAL=NULLDACL", 16) == 0) {
            out->special = FIM_ACL_NULLDACL;
            break;
        }
        if (strncmp(line, "... truncated", 13) == 0) {
            continue;
        }
        if (sscanf(line, "%u|%191[^|]|%d|%u|%u", &ord, sid, &type, &flags, &mask) == 5) {
            /* New format with original order. */
        } else if (sscanf(line, "%191[^|]|%d|%u|%u", sid, &type, &flags, &mask) == 4) {
            ord = (unsigned int)n;
        } else {
            continue;
        }
        memset(&ace, 0, sizeof(ace));
        snprintf(ace.sid, sizeof(ace.sid), "%s", sid);
        ace.type = type;
        ace.flags = flags;
        ace.mask = mask;
        ace.ord = ord;
        if (n >= cap) {
            fim_ace_t *neu;
            cap *= 2;
            neu = realloc(out->aces, cap * sizeof(fim_ace_t));
            if (!neu) {
                free(copy);
                fim_acl_free(out);
                return (-1);
            }
            out->aces = neu;
        }
        out->aces[n++] = ace;
    }
    out->count = n;
    free(copy);
    fim_acl_sort(out);
    return (0);
}

int fim_win_acl_digest(const fim_acl_t *acl, char *md5_hex33)
{
    char *snap;
    os_md5 md5;

    if (!acl || !md5_hex33) {
        return (-1);
    }
    if (acl->special == FIM_ACL_NODACL) {
        OS_MD5_Str("NODACL", md5);
        memcpy(md5_hex33, md5, 33);
        return (0);
    }
    if (acl->special == FIM_ACL_NULLDACL) {
        OS_MD5_Str("NULLDACL", md5);
        memcpy(md5_hex33, md5, 33);
        return (0);
    }

    snap = fim_win_acl_snapshot_dup(acl);
    if (!snap) {
        return (-1);
    }
    OS_MD5_Str(snap, md5);
    memcpy(md5_hex33, md5, 33);
    free(snap);
    return (0);
}

static void format_one_ace(const fim_ace_t *a, char *line, size_t linelen, int with_name)
{
    char inh[32];
    char rights[512];
    char who[256];
    const char *kind;

    if (a->type == FIM_ACE_OTHER) {
        snprintf(line, linelen, "OPAQUE %s (type/mask encoded)", a->sid);
        return;
    }

    kind = (a->type == FIM_ACE_DENY) ? "DENIED" : "ALLOWED";
    format_inherit(a->flags, inh, sizeof(inh));
    format_mask(a->mask, rights, sizeof(rights));
    if (with_name) {
        sid_to_name(a->sid, who, sizeof(who));
    } else {
        snprintf(who, sizeof(who), "%s", a->sid);
    }
    snprintf(line, linelen, "%s (%s) [%s] - %s", who, kind, inh, rights);
}

int fim_win_acl_format(const fim_acl_t *acl, char *buf, size_t buflen)
{
    size_t used = 0;
    size_t i;
    char line[768];

    if (!acl || !buf || buflen == 0) {
        return (-1);
    }
    buf[0] = '\0';
    append_str(buf, buflen, &used, "Permissions:\n");

    if (acl->special == FIM_ACL_NODACL) {
        append_str(buf, buflen, &used, "  (no DACL)\n");
        return ((int)used);
    }
    if (acl->special == FIM_ACL_NULLDACL) {
        append_str(buf, buflen, &used, "  (null DACL - unrestricted)\n");
        return ((int)used);
    }

    for (i = 0; i < acl->count; i++) {
        int len;

        format_one_ace(&acl->aces[i], line, sizeof(line), 1);
        len = (int)strlen(line);
        if (used + 2 + (size_t)len + 1 + sizeof("  ... truncated ...\n") >= buflen) {
            append_str(buf, buflen, &used, "  ... truncated ...\n");
            break;
        }
        append_str(buf, buflen, &used, "  ");
        append_str(buf, buflen, &used, line);
        append_str(buf, buflen, &used, "\n");
    }
    return ((int)used);
}

static int ace_same_principal(const fim_ace_t *a, const fim_ace_t *b)
{
    return (strcmp(a->sid, b->sid) == 0 && a->type == b->type &&
            a->flags == b->flags);
}

int fim_win_acl_diff(const fim_acl_t *old_acl, const fim_acl_t *new_acl,
                     char *buf, size_t buflen)
{
    size_t used = 0;
    size_t i, j;
    char line[768];
    int any = 0;

    if (!old_acl || !new_acl || !buf || buflen == 0) {
        return (-1);
    }
    buf[0] = '\0';

    if (old_acl->special != new_acl->special) {
        /* Keep "Permissions:" prefix so analysisd does not label this as
         * a content-diff "What changed:" appendix. */
        append_str(buf, buflen, &used, "Permissions:\n");
        append_str(buf, buflen, &used, "  DACL state changed\n");
        fim_win_acl_format(new_acl, buf + used,
                           buflen > used ? buflen - used : 0);
        return ((int)strlen(buf));
    }
    if (old_acl->special != FIM_ACL_NORMAL) {
        /* identical special states */
        return (0);
    }

    append_str(buf, buflen, &used, "Permissions:\n");

    /* Track which new ACEs have been paired so duplicate principals
     * (same SID/type/flags, different masks) map 1:1. */
    {
        unsigned char *new_used = NULL;

        if (new_acl->count > 0) {
            new_used = calloc(new_acl->count, 1);
            if (!new_used) {
                return (-1);
            }
        }

        /* Removed / modified */
        for (i = 0; i < old_acl->count; i++) {
            const fim_ace_t *o = &old_acl->aces[i];
            int found = 0;

            for (j = 0; j < new_acl->count; j++) {
                const fim_ace_t *n = &new_acl->aces[j];

                if (new_used && new_used[j]) {
                    continue;
                }
                if (!ace_same_principal(o, n)) {
                    continue;
                }
                found = 1;
                if (new_used) {
                    new_used[j] = 1;
                }
                if (o->mask != n->mask || o->ord != n->ord) {
                    append_str(buf, buflen, &used, "  Modified: ");
                    format_one_ace(o, line, sizeof(line), 1);
                    append_str(buf, buflen, &used, line);
                    append_str(buf, buflen, &used, " -> ");
                    format_one_ace(n, line, sizeof(line), 1);
                    append_str(buf, buflen, &used, line);
                    append_str(buf, buflen, &used, "\n");
                    any = 1;
                }
                break;
            }
            if (!found) {
                append_str(buf, buflen, &used, "  Removed: ");
                format_one_ace(o, line, sizeof(line), 1);
                append_str(buf, buflen, &used, line);
                append_str(buf, buflen, &used, "\n");
                any = 1;
            }
            if (used + 128 >= buflen) {
                append_str(buf, buflen, &used, "  ... truncated ...\n");
                free(new_used);
                return ((int)used);
            }
        }

        /* Added */
        for (j = 0; j < new_acl->count; j++) {
            const fim_ace_t *n = &new_acl->aces[j];

            if (new_used && new_used[j]) {
                continue;
            }
            append_str(buf, buflen, &used, "  Added: ");
            format_one_ace(n, line, sizeof(line), 1);
            append_str(buf, buflen, &used, line);
            append_str(buf, buflen, &used, "\n");
            any = 1;
            if (used + 128 >= buflen) {
                append_str(buf, buflen, &used, "  ... truncated ...\n");
                free(new_used);
                return ((int)used);
            }
        }
        free(new_used);
    }

    if (!any) {
        /* No ACE-level differences (identical principals/masks). */
        buf[0] = '\0';
        return (0);
    }
    return ((int)used);
}

int fim_win_acl_change_text(const char *old_sum_entry, const char *new_sum_entry,
                            char *buf, size_t buflen)
{
    const char *old_nl;
    const char *new_nl;
    fim_acl_t old_acl;
    fim_acl_t new_acl;
    char old_dig[40];
    char new_dig[40];
    int rc;
    int have_old_dig;
    int have_new_dig;

    if (!old_sum_entry || !new_sum_entry || !buf || buflen == 0) {
        return (-1);
    }
    buf[0] = '\0';

    /* Only emit appendix text when the ACL digest field actually changed
     * (or ACL tracking is newly present). Avoid attaching a full matrix on
     * unrelated size/hash alerts. */
    have_old_dig = (fim_sum_get_field(old_sum_entry, 8, old_dig, sizeof(old_dig)) == 0);
    have_new_dig = (fim_sum_get_field(new_sum_entry, 8, new_dig, sizeof(new_dig)) == 0);
    if (!have_new_dig) {
        return (0);
    }
    if (have_old_dig && strcmp(old_dig, new_dig) == 0) {
        return (0);
    }

    new_nl = strchr(new_sum_entry, '\n');
    if (!new_nl || !new_nl[1]) {
        return (0);
    }
    new_nl++;

    old_nl = strchr(old_sum_entry, '\n');
    memset(&old_acl, 0, sizeof(old_acl));
    memset(&new_acl, 0, sizeof(new_acl));

    if (fim_win_acl_parse_snapshot(new_nl, &new_acl) != 0) {
        return (-1);
    }

    if (old_nl && old_nl[1]) {
        if (fim_win_acl_parse_snapshot(old_nl + 1, &old_acl) != 0) {
            fim_acl_free(&new_acl);
            return (-1);
        }
        rc = fim_win_acl_diff(&old_acl, &new_acl, buf, buflen);
        fim_acl_free(&old_acl);
        if (rc <= 0) {
            /* Digests differ but ACE walk found nothing (e.g. truncation) —
             * fall back to the full new matrix. */
            rc = fim_win_acl_format(&new_acl, buf, buflen);
        }
        fim_acl_free(&new_acl);
        return (rc);
    }

    /* First ACL observation for this path: show the full matrix. */
    rc = fim_win_acl_format(&new_acl, buf, buflen);
    fim_acl_free(&new_acl);
    return (rc);
}

#ifdef WIN32
int fim_win_acl_read(const char *path, fim_acl_t *out)
{
    PSECURITY_DESCRIPTOR pSD = NULL;
    PACL pDacl = NULL;
    BOOL present = FALSE;
    BOOL defaulted = FALSE;
    ACL_SIZE_INFORMATION info;
    DWORD i;
    size_t cap = 16;
    size_t n = 0;
    LONG rc;

    if (!path || !out) {
        return (-1);
    }
    memset(out, 0, sizeof(*out));
    out->aces = calloc(cap, sizeof(fim_ace_t));
    if (!out->aces) {
        return (-1);
    }

    rc = GetNamedSecurityInfoA((LPSTR)path, SE_FILE_OBJECT,
                               DACL_SECURITY_INFORMATION,
                               NULL, NULL, &pDacl, NULL, &pSD);
    if (rc != ERROR_SUCCESS) {
        fim_acl_free(out);
        return (-1);
    }

    if (!GetSecurityDescriptorDacl(pSD, &present, &pDacl, &defaulted)) {
        LocalFree(pSD);
        fim_acl_free(out);
        return (-1);
    }

    if (!present) {
        out->special = FIM_ACL_NODACL;
        LocalFree(pSD);
        return (0);
    }
    if (pDacl == NULL) {
        out->special = FIM_ACL_NULLDACL;
        LocalFree(pSD);
        return (0);
    }

    if (!GetAclInformation(pDacl, &info, sizeof(info), AclSizeInformation)) {
        LocalFree(pSD);
        fim_acl_free(out);
        return (-1);
    }

    for (i = 0; i < info.AceCount; i++) {
        ACE_HEADER *hdr = NULL;
        fim_ace_t ace;
        PSID sid = NULL;
        LPSTR sid_str = NULL;

        if (!GetAce(pDacl, i, (LPVOID *)&hdr) || !hdr) {
            continue;
        }

        memset(&ace, 0, sizeof(ace));
        ace.ord = (unsigned int)i;
        ace.flags = hdr->AceFlags &
                    (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE |
                     NO_PROPAGATE_INHERIT_ACE | INHERIT_ONLY_ACE |
                     INHERITED_ACE);

        if (hdr->AceType == ACCESS_ALLOWED_ACE_TYPE ||
                hdr->AceType == ACCESS_DENIED_ACE_TYPE) {
            ace.type = (hdr->AceType == ACCESS_DENIED_ACE_TYPE) ?
                       FIM_ACE_DENY : FIM_ACE_ALLOW;

            if (hdr->AceType == ACCESS_ALLOWED_ACE_TYPE) {
                ACCESS_ALLOWED_ACE *a = (ACCESS_ALLOWED_ACE *)hdr;
                ace.mask = a->Mask;
                sid = (PSID)&a->SidStart;
            } else {
                ACCESS_DENIED_ACE *a = (ACCESS_DENIED_ACE *)hdr;
                ace.mask = a->Mask;
                sid = (PSID)&a->SidStart;
            }

            if (!ConvertSidToStringSidA(sid, &sid_str) || !sid_str) {
                LocalFree(pSD);
                fim_acl_free(out);
                return (-1);
            }
            snprintf(ace.sid, sizeof(ace.sid), "%s", sid_str);
            LocalFree(sid_str);
        } else {
            /* Callback/object/unknown ACE: include an opaque digest so the
             * integrity hash still changes when these entries change. */
            os_md5 ace_md5;
            const unsigned char *raw = (const unsigned char *)hdr;
            size_t raw_len = hdr->AceSize;

            ace.type = FIM_ACE_OTHER;
            ace.mask = hdr->AceType;
            if (raw_len == 0 || raw_len > 65535) {
                raw_len = sizeof(ACE_HEADER);
            }
            if (OS_MD5_Bytes((const char *)raw, raw_len, ace_md5) != 0) {
                LocalFree(pSD);
                fim_acl_free(out);
                return (-1);
            }
            snprintf(ace.sid, sizeof(ace.sid), "TYPE%u_%s",
                     (unsigned int)hdr->AceType, ace_md5);
        }

        if (n >= cap) {
            fim_ace_t *neu;
            cap *= 2;
            neu = realloc(out->aces, cap * sizeof(fim_ace_t));
            if (!neu) {
                LocalFree(pSD);
                fim_acl_free(out);
                return (-1);
            }
            out->aces = neu;
        }
        out->aces[n++] = ace;
    }

    out->count = n;
    LocalFree(pSD);
    fim_acl_sort(out);
    return (0);
}
#else
int fim_win_acl_read(const char *path, fim_acl_t *out)
{
    (void)path;
    if (out) {
        memset(out, 0, sizeof(*out));
    }
    return (-1);
}
#endif
