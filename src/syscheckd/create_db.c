/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "syscheck.h"
#include "fim_sum_op.h"
#include "win_acl_op.h"
#include "os_crypto/md5/md5_op.h"
#include "os_crypto/sha1/sha1_op.h"
#include "os_crypto/sha256/sha256_op.h"
#include "os_crypto/md5_sha1/md5_sha1_op.h"
#ifdef WIN32
#include <aclapi.h>
#include <sddl.h>
#endif

/* Prototypes */
static int read_file(const char *dir_name, int opts, OSMatch *restriction)  __attribute__((nonnull(1)));

/* Global variables */
static int __counter = 0;


/* Read and generate the integrity data of a file */
static int read_file(const char *file_name, int opts, OSMatch *restriction)
{
    char *buf;
    char sha1s;
    struct stat statbuf;

    /* Check if the file should be ignored */
    if (syscheck.ignore) {
        int i = 0;
        while (syscheck.ignore[i] != NULL) {
            if (strncasecmp(syscheck.ignore[i], file_name,
                            strlen(syscheck.ignore[i])) == 0) {
                return (0);
            }
            i++;
        }
    }

    /* Check in the regex entry */
    if (syscheck.ignore_regex) {
        int i = 0;
        while (syscheck.ignore_regex[i] != NULL) {
            if (OSMatch_Execute(file_name, strlen(file_name),
                                syscheck.ignore_regex[i])) {
                return (0);
            }
            i++;
        }
    }

#ifdef WIN32
    /* Win32 does not have lstat */
    if (stat(file_name, &statbuf) < 0)
#else
    if (lstat(file_name, &statbuf) < 0)
#endif
    {
        if(errno == ENOTDIR){
		/*Deletion message sending*/
		char alert_msg[PATH_MAX+4];
		alert_msg[PATH_MAX + 3] = '\0';
		snprintf(alert_msg, PATH_MAX + 4, "-1 %s", file_name);
		send_syscheck_msg(alert_msg);
		return (0);
	}else{
		merror("%s: Error accessing '%s'.", ARGV0, file_name);
		return (-1);
	}
    }

    if (S_ISDIR(statbuf.st_mode)) {
#ifdef DEBUG
        verbose("%s: Reading dir: %s\n", ARGV0, file_name);
#endif

#ifdef WIN32
        /* Directory links are not supported */
        if (GetFileAttributes(file_name) & FILE_ATTRIBUTE_REPARSE_POINT) {
            merror("%s: WARN: Links are not supported: '%s'", ARGV0, file_name);
            return (-1);
        }
#endif
        return (read_dir(file_name, opts, restriction));
    }

    /* Restrict file types */
    if (restriction) {
        if (!OSMatch_Execute(file_name, strlen(file_name),
                             restriction)) {
            return (0);
        }
    }

    /* No S_ISLNK on Windows */
#ifdef WIN32
    if (S_ISREG(statbuf.st_mode))
#else
    if (S_ISREG(statbuf.st_mode) || S_ISLNK(statbuf.st_mode))
#endif
    {
        os_md5 mf_sum;
        os_sha1 sf_sum;
        os_sha256 sha256_sum;
        os_sha1 sf_sum2;
        os_sha1 sf_sum3;

        /* Clean sums */
        strncpy(mf_sum,  "xxx", 4);
        strncpy(sf_sum,  "xxx", 4);
        strncpy(sha256_sum,  "xxx", 4);
        strncpy(sf_sum2, "xxx", 4);
        strncpy(sf_sum3, "xxx", 4);

        /* Generate checksums */
        if ((opts & CHECK_MD5SUM) || (opts & CHECK_SHA1SUM) || (opts & CHECK_SHA256SUM)) {
            /* If it is a link, check if dest is valid */
#ifndef WIN32
            if (S_ISLNK(statbuf.st_mode)) {
                struct stat statbuf_lnk;
                if (stat(file_name, &statbuf_lnk) == 0) {
                    if (S_ISREG(statbuf_lnk.st_mode)) {
                        if ((opts & CHECK_MD5SUM) || (opts & CHECK_SHA1SUM)) {
                            if (OS_MD5_SHA1_File(file_name, syscheck.prefilter_cmd, mf_sum, sf_sum, OS_BINARY) < 0) {
                                merror("%s: WARN: Unable to read file '%s' for checksum: %s",
                                       ARGV0, file_name, strerror(errno));
                                strncpy(mf_sum, "xxx", 4);
                                strncpy(sf_sum, "xxx", 4);
                            }
                        }
                        if (opts & CHECK_SHA256SUM) {
                            if (OS_SHA256_File(file_name, sha256_sum, OS_BINARY) < 0) {
                                merror("%s: WARN: Unable to read file '%s' for sha256: %s",
                                       ARGV0, file_name, strerror(errno));
                                strncpy(sha256_sum, "xxx", 4);
                            }
                        }
                    }
                }
            } else {
                 if ((opts & CHECK_MD5SUM) || (opts & CHECK_SHA1SUM)) {
                     if (OS_MD5_SHA1_File(file_name, syscheck.prefilter_cmd, mf_sum, sf_sum, OS_BINARY) < 0) {
                        merror("%s: WARN: Unable to read file '%s' for checksum: %s",
                               ARGV0, file_name, strerror(errno));
                        strncpy(mf_sum, "xxx", 4);
                        strncpy(sf_sum, "xxx", 4);
                     }
                 }
                 if (opts & CHECK_SHA256SUM) {
                    if (OS_SHA256_File(file_name, sha256_sum, OS_BINARY) < 0) {
                        merror("%s: WARN: Unable to read file '%s' for sha256: %s",
                               ARGV0, file_name, strerror(errno));
                        strncpy(sha256_sum, "xxx", 4);
                    }
                 }
            }
#else
            if ((opts & CHECK_MD5SUM) || (opts & CHECK_SHA1SUM)) {
                if (OS_MD5_SHA1_File(file_name, syscheck.prefilter_cmd, mf_sum, sf_sum, OS_BINARY) < 0)
                {
                    merror("%s: WARN: Unable to read file '%s' for checksum: %s",
                           ARGV0, file_name, strerror(errno));
                    strncpy(mf_sum, "xxx", 4);
                    strncpy(sf_sum, "xxx", 4);
                }
            }
            if (opts & CHECK_SHA256SUM) {
                if (OS_SHA256_File(file_name, sha256_sum, OS_BINARY) < 0) {
                    merror("%s: WARN: Unable to read file '%s' for sha256: %s",
                           ARGV0, file_name, strerror(errno));
                    strncpy(sha256_sum, "xxx", 4);
                }
            }
#endif

            if (opts & CHECK_SEECHANGES) {
                /* 's' = seechanges + sha1 on; 'n' = seechanges + sha1 off */
                sha1s = (opts & CHECK_SHA1SUM) ? 's' : 'n';
            } else {
                sha1s = (opts & CHECK_SHA1SUM) ? '+' : '-';
            }
        } else {
            if (opts & CHECK_SEECHANGES) {
                sha1s = 'n';
            } else {
                sha1s = '-';
            }
        }

        buf = (char *) OSHash_Get(syscheck.fp, file_name);
        if (!buf) {
            char alert_msg[OS_MAXSTR + 1];
            char hash_entry[916 + 1];
            char *hash_full = NULL;     /* optional ACL snapshot entry */
            alert_msg[OS_MAXSTR] = '\0';
            hash_entry[916] = '\0';
            hash_entry[0] = '\0';
            alert_msg[0] = '\0';

#ifndef WIN32
            if (opts & CHECK_SEECHANGES) {
                char *alertdump = seechanges_addfile(file_name);
                if (alertdump) {
                    free(alertdump);
                    alertdump = NULL;
                }
            }
#endif

#ifdef WIN32
            {
                DWORD win_attrs = 0;
                char acl_digest[33];
                char *acl_snap = NULL;
                fim_acl_t acl;
                int have_acl = 0;
                const char *uid_str;
                HANDLE hFile;
                PSID pSidOwner = NULL;
                PSECURITY_DESCRIPTOR pSD = NULL;
                DWORD dwRtnCode;
                LPSTR szSID = NULL;
                char *st_uid = NULL;

                acl_digest[0] = '\0';
                memset(&acl, 0, sizeof(acl));

                if (opts & CHECK_ATTRS) {
                    win_attrs = GetFileAttributes(file_name);
                    if (win_attrs == INVALID_FILE_ATTRIBUTES) {
                        merror("%s: WARN: Unable to get attributes for '%s' (%lu); "
                               "continuing without attribute baseline",
                               ARGV0, file_name, (unsigned long)GetLastError());
                        win_attrs = 0;
                    }
                }

                if (opts & CHECK_ACL) {
                    if (fim_win_acl_read(file_name, &acl) != 0) {
                        fim_acl_free(&acl);
                        merror("%s: WARN: Unable to read ACL for '%s'; "
                               "continuing without ACL baseline",
                               ARGV0, file_name);
                    } else if (fim_win_acl_digest(&acl, acl_digest) != 0 ||
                               (acl_snap = fim_win_acl_snapshot_dup(&acl)) == NULL) {
                        fim_acl_free(&acl);
                        free(acl_snap);
                        acl_snap = NULL;
                        merror("%s: WARN: Unable to digest ACL for '%s'; "
                               "continuing without ACL baseline",
                               ARGV0, file_name);
                        acl_digest[0] = '\0';
                    } else {
                        have_acl = 1;
                        fim_acl_free(&acl);
                    }
                }

                if (have_acl) {
                    /* 9-flag format: attrs slot always present (0 if unchecked). */
                    snprintf(hash_entry, 916,
                             "%c%c%c%c%c%c%c%c+%ld:%d:%d:%d:%s:%s:%s:%lu:%s",
                             opts & CHECK_SIZE ? '+' : '-',
                             opts & CHECK_PERM ? '+' : '-',
                             opts & CHECK_OWNER ? '+' : '-',
                             opts & CHECK_GROUP ? '+' : '-',
                             opts & CHECK_MD5SUM ? '+' : '-',
                             sha1s,
                             opts & CHECK_SHA256SUM ? '+' : '-',
                             opts & CHECK_ATTRS ? '+' : '-',
                             opts & CHECK_SIZE ? (long)statbuf.st_size : 0,
                             opts & CHECK_PERM ? (int)statbuf.st_mode : 0,
                             opts & CHECK_OWNER ? (int)statbuf.st_uid : 0,
                             opts & CHECK_GROUP ? (int)statbuf.st_gid : 0,
                             opts & CHECK_MD5SUM ? mf_sum : "xxx",
                             opts & CHECK_SHA1SUM ? sf_sum : "xxx",
                             opts & CHECK_SHA256SUM ? sha256_sum : "xxx",
                             (opts & CHECK_ATTRS) ? (unsigned long)win_attrs : 0UL,
                             acl_digest);
                    {
                        size_t he_len = strlen(hash_entry);
                        size_t snap_len = acl_snap ? strlen(acl_snap) : 0;

                        os_calloc(he_len + 1 + snap_len + 1, sizeof(char), hash_full);
                        memcpy(hash_full, hash_entry, he_len);
                        hash_full[he_len] = '\n';
                        if (acl_snap) {
                            memcpy(hash_full + he_len + 1, acl_snap, snap_len + 1);
                        } else {
                            hash_full[he_len + 1] = '\0';
                        }
                    }
                } else if (opts & CHECK_ATTRS) {
                    snprintf(hash_entry, 916,
                             "%c%c%c%c%c%c%c+%ld:%d:%d:%d:%s:%s:%s:%lu",
                             opts & CHECK_SIZE ? '+' : '-',
                             opts & CHECK_PERM ? '+' : '-',
                             opts & CHECK_OWNER ? '+' : '-',
                             opts & CHECK_GROUP ? '+' : '-',
                             opts & CHECK_MD5SUM ? '+' : '-',
                             sha1s,
                             opts & CHECK_SHA256SUM ? '+' : '-',
                             opts & CHECK_SIZE ? (long)statbuf.st_size : 0,
                             opts & CHECK_PERM ? (int)statbuf.st_mode : 0,
                             opts & CHECK_OWNER ? (int)statbuf.st_uid : 0,
                             opts & CHECK_GROUP ? (int)statbuf.st_gid : 0,
                             opts & CHECK_MD5SUM ? mf_sum : "xxx",
                             opts & CHECK_SHA1SUM ? sf_sum : "xxx",
                             opts & CHECK_SHA256SUM ? sha256_sum : "xxx",
                             (unsigned long)win_attrs);
                } else {
                    snprintf(hash_entry, 916, "%c%c%c%c%c%c%c%ld:%d:%d:%d:%s:%s:%s",
                             opts & CHECK_SIZE ? '+' : '-',
                             opts & CHECK_PERM ? '+' : '-',
                             opts & CHECK_OWNER ? '+' : '-',
                             opts & CHECK_GROUP ? '+' : '-',
                             opts & CHECK_MD5SUM ? '+' : '-',
                             sha1s,
                             opts & CHECK_SHA256SUM ? '+' : '-',
                             opts & CHECK_SIZE ? (long)statbuf.st_size : 0,
                             opts & CHECK_PERM ? (int)statbuf.st_mode : 0,
                             opts & CHECK_OWNER ? (int)statbuf.st_uid : 0,
                             opts & CHECK_GROUP ? (int)statbuf.st_gid : 0,
                             opts & CHECK_MD5SUM ? mf_sum : "xxx",
                             opts & CHECK_SHA1SUM ? sf_sum : "xxx",
                             opts & CHECK_SHA256SUM ? sha256_sum : "xxx");
                }

                /* Owner SID for the manager alert (reuse attrs/ACL above). */
                alert_msg[OS_MAXSTR] = '\0';
                hFile = CreateFile(file_name, GENERIC_READ,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                   NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                if (hFile == INVALID_HANDLE_VALUE) {
                    DWORD dwErrorCode = GetLastError();
                    char err_msg[PATH_MAX + 4];
                    free(hash_full);
                    free(acl_snap);
                    err_msg[PATH_MAX + 3] = '\0';
                    snprintf(err_msg, PATH_MAX + 4, "CreateFile=%ld %s",
                             dwErrorCode, file_name);
                    send_syscheck_msg(err_msg);
                    return -1;
                }

                dwRtnCode = GetSecurityInfo(hFile, SE_FILE_OBJECT,
                                            OWNER_SECURITY_INFORMATION,
                                            &pSidOwner, NULL, NULL, NULL, &pSD);
                if (dwRtnCode != ERROR_SUCCESS) {
                    DWORD dwErrorCode = GetLastError();
                    CloseHandle(hFile);
                    free(hash_full);
                    free(acl_snap);
                    {
                        char err_msg[PATH_MAX + 4];
                        err_msg[PATH_MAX + 3] = '\0';
                        snprintf(err_msg, PATH_MAX + 4, "GetSecurityInfo=%ld %s",
                                 dwErrorCode, file_name);
                        send_syscheck_msg(err_msg);
                    }
                    return -1;
                }

                ConvertSidToStringSid(pSidOwner, &szSID);
                if (szSID) {
                    st_uid = (char *)calloc(strlen(szSID) + 1, 1);
                    memcpy(st_uid, szSID, strlen(szSID));
                }
                LocalFree(szSID);
                if (pSD) {
                    LocalFree(pSD);
                }
                CloseHandle(hFile);

                uid_str = (opts & CHECK_OWNER) ? (st_uid ? st_uid : "0") : "0";

                if (have_acl) {
                    snprintf(alert_msg, OS_MAXSTR, "%ld:%d:%s:%d:%s:%s:%s:%lu:%s %s",
                             opts & CHECK_SIZE ? (long)statbuf.st_size : 0,
                             opts & CHECK_PERM ? (int)statbuf.st_mode : 0,
                             uid_str,
                             opts & CHECK_GROUP ? (int)statbuf.st_gid : 0,
                             opts & CHECK_MD5SUM ? mf_sum : "xxx",
                             opts & CHECK_SHA1SUM ? sf_sum : "xxx",
                             opts & CHECK_SHA256SUM ? sha256_sum : "xxx",
                             (opts & CHECK_ATTRS) ? (unsigned long)win_attrs : 0UL,
                             acl_digest,
                             file_name);
                } else if (opts & CHECK_ATTRS) {
                    snprintf(alert_msg, OS_MAXSTR, "%ld:%d:%s:%d:%s:%s:%s:%lu %s",
                             opts & CHECK_SIZE ? (long)statbuf.st_size : 0,
                             opts & CHECK_PERM ? (int)statbuf.st_mode : 0,
                             uid_str,
                             opts & CHECK_GROUP ? (int)statbuf.st_gid : 0,
                             opts & CHECK_MD5SUM ? mf_sum : "xxx",
                             opts & CHECK_SHA1SUM ? sf_sum : "xxx",
                             opts & CHECK_SHA256SUM ? sha256_sum : "xxx",
                             (unsigned long)win_attrs,
                             file_name);
                } else {
                    snprintf(alert_msg, OS_MAXSTR, "%ld:%d:%s:%d:%s:%s:%s %s",
                             opts & CHECK_SIZE ? (long)statbuf.st_size : 0,
                             opts & CHECK_PERM ? (int)statbuf.st_mode : 0,
                             uid_str,
                             opts & CHECK_GROUP ? (int)statbuf.st_gid : 0,
                             opts & CHECK_MD5SUM ? mf_sum : "xxx",
                             opts & CHECK_SHA1SUM ? sf_sum : "xxx",
                             opts & CHECK_SHA256SUM ? sha256_sum : "xxx",
                             file_name);
                }
                free(st_uid);
                free(acl_snap);
                acl_snap = NULL;
            }
#else
            snprintf(hash_entry, 916, "%c%c%c%c%c%c%c%ld:%d:%d:%d:%s:%s:%s",
                     opts & CHECK_SIZE ? '+' : '-',
                     opts & CHECK_PERM ? '+' : '-',
                     opts & CHECK_OWNER ? '+' : '-',
                     opts & CHECK_GROUP ? '+' : '-',
                     opts & CHECK_MD5SUM ? '+' : '-',
                     sha1s,
                     opts & CHECK_SHA256SUM ? '+' : '-',
                     opts & CHECK_SIZE ? (long)statbuf.st_size : 0,
                     opts & CHECK_PERM ? (int)statbuf.st_mode : 0,
                     opts & CHECK_OWNER ? (int)statbuf.st_uid : 0,
                     opts & CHECK_GROUP ? (int)statbuf.st_gid : 0,
                     opts & CHECK_MD5SUM ? mf_sum : "xxx",
                     opts & CHECK_SHA1SUM ? sf_sum : "xxx",
                     opts & CHECK_SHA256SUM ? sha256_sum : "xxx");

            alert_msg[916] = '\0';
            snprintf(alert_msg, 916, "%ld:%d:%d:%d:%s:%s:%s %s",
                     opts & CHECK_SIZE ? (long)statbuf.st_size : 0,
                     opts & CHECK_PERM ? (int)statbuf.st_mode : 0,
                     opts & CHECK_OWNER ? (int)statbuf.st_uid : 0,
                     opts & CHECK_GROUP ? (int)statbuf.st_gid : 0,
                     opts & CHECK_MD5SUM ? mf_sum : "xxx",
                     opts & CHECK_SHA1SUM ? sf_sum : "xxx",
                     opts & CHECK_SHA256SUM ? sha256_sum : "xxx",
                     file_name);
#endif
            if (send_syscheck_msg(alert_msg) == 0) {
                char *to_store = hash_full ? hash_full : strdup(hash_entry);
                hash_full = NULL;
                if (!to_store || OSHash_Add(syscheck.fp, file_name, to_store) <= 0) {
                    free(to_store);
                    merror("%s: ERROR: Unable to add file to db: %s", ARGV0, file_name);
                }
            } else {
                free(hash_full);
                merror("%s: WARN: Failed to send syscheck baseline for '%s'. "
                      "File will be retried on the next scan.", ARGV0, file_name);
            }
        } else {
            char alert_msg[OS_MAXSTR + 1];
            char c_sum[OS_MAXSTR + 1];

            c_sum[0] = '\0';
            c_sum[OS_MAXSTR] = '\0';
            alert_msg[0] = '\0';
            alert_msg[OS_MAXSTR] = '\0';

#ifdef WIN32
            /* Keep local cache flag format aligned with current directory opts. */
            {
                int cur_off = fim_sum_data_offset(buf);
                int want_attrs = (opts & CHECK_ATTRS) ? 1 : 0;
                int want_acl = (opts & CHECK_ACL) ? 1 : 0;
                int need = 7;

                if (want_acl) {
                    need = 9;
                } else if (want_attrs) {
                    need = 8;
                }

                if (cur_off != need ||
                        (need >= 8 && ((buf[7] == '+') != want_attrs)) ||
                        (need >= 9 && ((buf[8] == '+') != want_acl))) {
                    char *upgraded;
                    size_t blen = strlen(buf);
                    size_t data_len = (blen > (size_t)cur_off) ? (blen - (size_t)cur_off) : 0;

                    os_calloc((size_t)need + data_len + 1, sizeof(char), upgraded);
                    /* Copy only the old flag prefix — never pull size digits
                     * from legacy 6-flag entries into the flag slots. */
                    {
                        size_t flag_copy = (cur_off < 7) ? (size_t)cur_off : 7;

                        memcpy(upgraded, buf, flag_copy);
                        if (cur_off < 7) {
                            upgraded[6] = (opts & CHECK_SHA256SUM) ? '+' : '-';
                        }
                    }
                    if (need >= 8) {
                        upgraded[7] = want_attrs ? '+' : '-';
                    }
                    if (need >= 9) {
                        upgraded[8] = want_acl ? '+' : '-';
                    }
                    if (data_len > 0) {
                        memcpy(upgraded + need, buf + cur_off, data_len + 1);
                    } else {
                        upgraded[need] = '\0';
                    }
                    if (OSHash_Update(syscheck.fp, file_name, upgraded) == 1) {
                        free(buf);
                        buf = upgraded;
                    } else {
                        free(upgraded);
                    }
                }
            }
#endif

            /* If it returns < 0, we have already alerted (missing file) or
             * skipped (checksum read failure). */
            if (c_read_file(file_name, buf, c_sum) < 0) {
                return (0);
            }

            {
                int sum_off = fim_sum_data_offset(buf);

                if (!fim_sum_equal(c_sum, buf + sum_off)) {
                    int real_change = fim_sum_has_real_change(buf + sum_off, c_sum);

                    if (real_change) {
                        /* Real integrity change: notify the manager first. */
                        alert_msg[OS_MAXSTR] = '\0';
                        #ifdef WIN32
                        {
                            char *sum_only = NULL;
                            char *acl_txt = NULL;
                            size_t slen = fim_sum_data_len(c_sum);

                            os_calloc(OS_MAXSTR + 1, sizeof(char), sum_only);
                            os_calloc(OS_MAXSTR + 1, sizeof(char), acl_txt);
                            if (slen > (size_t)OS_MAXSTR) {
                                slen = (size_t)OS_MAXSTR;
                            }
                            memcpy(sum_only, c_sum, slen);
                            sum_only[slen] = '\0';

                            /* fim_win_acl_change_text() already no-ops unless the
                             * new sum carries an ACL digest/snapshot that changed,
                             * so do not gate on sum_off (legacy 7/8-flag cache). */
                            if (fim_win_acl_change_text(buf + sum_off, c_sum,
                                                        acl_txt, (size_t)OS_MAXSTR + 1) > 0) {
                                snprintf(alert_msg, OS_MAXSTR, "%s %s\n%s",
                                         sum_only, file_name, acl_txt);
                            } else {
                                snprintf(alert_msg, OS_MAXSTR, "%s %s", sum_only, file_name);
                            }
                            free(sum_only);
                            free(acl_txt);
                        }
                        #else
                        char *fullalert = NULL;
                        if (buf[5] == 's' || buf[5] == 'n') {
                            fullalert = seechanges_addfile(file_name);
                            if (fullalert) {
                                snprintf(alert_msg, OS_MAXSTR, "%s %s\n%s", c_sum, file_name, fullalert);
                                free(fullalert);
                                fullalert = NULL;
                            } else {
                                snprintf(alert_msg, 916, "%s %s", c_sum, file_name);
                            }
                        } else {
                            snprintf(alert_msg, 916, "%s %s", c_sum, file_name);
                        }
                        #endif
                        if (send_syscheck_msg(alert_msg) != 0) {
                            merror("%s: WARN: Failed to send syscheck update for '%s'. "
                                  "Change will be retried on the next scan.", ARGV0, file_name);
                            return (0);
                        }
                    }

                    /* Heal/refresh local cache after a successful send, or for
                     * placeholder-only transitions that need no manager alert. */
                    {
                        char *updated;
                        char *old_data = buf;
                        int nflags;
                        int fields = 1;
                        size_t clen = fim_sum_data_len(c_sum);
                        size_t i;

                        for (i = 0; i < clen; i++) {
                            if (c_sum[i] == ':') {
                                fields++;
                            }
                        }
                        if (fields >= 9) {
                            nflags = 9;
                        } else if (fields >= 8) {
                            nflags = 8;
                        } else {
                            nflags = 7;
                        }

                        os_calloc((size_t)nflags + strlen(c_sum) + 1, sizeof(char), updated);
                        /* Copy only the old flag prefix — never pull size digits
                         * from legacy 6-flag entries into the flag slots. */
                        {
                            size_t flag_copy = (sum_off < 7) ? (size_t)sum_off : 7;

                            memcpy(updated, buf, flag_copy);
                            if (sum_off < 7) {
                                /* Legacy cache had no sha256 enable flag. */
                                updated[6] = '-';
                            }
                        }
                        if (nflags >= 8) {
                            updated[7] = (fields >= 8) ? '+' : '-';
                            /* When only ACL forced the attrs slot, keep the slot
                             * disabled unless the old entry marked attrs enabled. */
                            if (fields == 9 && (sum_off < 8 || buf[7] != '+')) {
                                updated[7] = '-';
                            }
                        }
                        if (nflags >= 9) {
                            updated[8] = '+';
                        }
                        memcpy(updated + nflags, c_sum, strlen(c_sum) + 1);
                        if (OSHash_Update(syscheck.fp, file_name, updated) == 1) {
                            free(old_data);
                        } else {
                            free(updated);
                        }
                    }
                }
            }
        }

        /* Sleep here too */
        if (__counter >= (syscheck.sleep_after)) {
            sleep(syscheck.tsleep);
            __counter = 0;
        }
        __counter++;

#ifdef DEBUG
        verbose("%s: file '%s %s'", ARGV0, file_name, mf_sum);
#endif
    } else {
#ifdef DEBUG
        verbose("%s: *** IRREG file: '%s'\n", ARGV0, file_name);
#endif
    }

    return (0);
}

int read_dir(const char *dir_name, int opts, OSMatch *restriction)
{
    size_t dir_size;
    char f_name[PATH_MAX + 2];
    short is_nfs;

    DIR *dp;
    struct dirent *entry;

    f_name[PATH_MAX + 1] = '\0';

    /* Directory should be valid */
    if ((dir_size = strlen(dir_name)) > PATH_MAX) {
        merror(NULL_ERROR, ARGV0);
        return (-1);
    }

    /* Should we check for NFS? */
    if(syscheck.skip_nfs)
    {
        is_nfs = IsNFS(dir_name);
        if(is_nfs != 0)
        {
            // Error will be -1, and 1 means skipped
            return(is_nfs);
        }
    }


    /* Open the directory given */
    dp = opendir(dir_name);
    if (!dp) {
        if (errno == ENOTDIR) {
            if (read_file(dir_name, opts, restriction) == 0) {
                return (0);
            }
        }

#ifdef WIN32
        int di = 0;
        char *(defaultfilesn[]) = {
            "C:/autoexec.bat",
            "C:/config.sys",
            "C:/WINDOWS/System32/eventcreate.exe",
            "C:/WINDOWS/System32/eventtriggers.exe",
            "C:/WINDOWS/System32/tlntsvr.exe",
            "C:/WINDOWS/System32/Tasks",
            NULL
        };
        while (defaultfilesn[di] != NULL) {
            if (strcmp(defaultfilesn[di], dir_name) == 0) {
                break;
            }
            di++;
        }

        if (defaultfilesn[di] == NULL) {
            merror("%s: WARN: Error opening directory: '%s': %s ",
                   ARGV0, dir_name, strerror(errno));
        }
#else
        merror("%s: WARN: Error opening directory: '%s': %s ",
               ARGV0,
               dir_name,
               strerror(errno));
#endif /* WIN32 */
        return (-1);
    }

    /* Check for real time flag */
    if (opts & CHECK_REALTIME) {
#if defined(INOTIFY_ENABLED) || defined(WIN32)
        realtime_adddir(dir_name, opts);
#else
        merror("%s: WARN: realtime monitoring request on unsupported system for '%s'",
                ARGV0,
                dir_name
        );
#endif
    }

    while ((entry = readdir(dp)) != NULL) {
        char *s_name;

        /* Ignore . and ..  */
        if ((strcmp(entry->d_name, ".") == 0) ||
                (strcmp(entry->d_name, "..") == 0)) {
            continue;
        }

        strncpy(f_name, dir_name, PATH_MAX);
        s_name =  f_name;
        s_name += dir_size;

        /* Check if the file name is already null terminated */
        if (*(s_name - 1) != '/') {
            *s_name++ = '/';
        }

        *s_name = '\0';
        strncpy(s_name, entry->d_name, PATH_MAX - dir_size - 2);

        /* Check if the file is a directory */
        if(opts & CHECK_NORECURSE) {
            struct stat recurse_sb;
            if((stat(f_name, &recurse_sb)) < 0) {
                merror("%s: ERR: Cannot stat %s: %s", ARGV0, f_name, strerror(errno));
            } else {
                switch (recurse_sb.st_mode & S_IFMT) {
                    case S_IFDIR:
                        continue;
                        break;
                }
            }
        }


        /* Check integrity of the file */
        read_file(f_name, opts, restriction);
    }

    closedir(dp);
    return (0);
}

int run_dbcheck()
{
    int i = 0;

    __counter = 0;
    while (syscheck.dir[i] != NULL) {
        read_dir(syscheck.dir[i], syscheck.opts[i], syscheck.filerestrict[i]);
        i++;
    }

    return (0);
}

int create_db()
{
    int i = 0;

    /* Create store data */
    syscheck.fp = OSHash_Create();
    if (!syscheck.fp) {
        ErrorExit("%s: Unable to create syscheck database."
                  ". Exiting.", ARGV0);
    }

    if (!OSHash_setSize(syscheck.fp, 2048)) {
        merror(LIST_ERROR, ARGV0);
        return (0);
    }

    if ((syscheck.dir == NULL) || (syscheck.dir[0] == NULL)) {
        merror("%s: No directories to check.", ARGV0);
        return (-1);
    }

    merror("%s: INFO: Starting syscheck database (pre-scan).", ARGV0);

    /* Read all available directories */
    __counter = 0;
    do {
        if (read_dir(syscheck.dir[i], syscheck.opts[i], syscheck.filerestrict[i]) == 0) {
            debug2("%s: Directory loaded from syscheck db: %s", ARGV0, syscheck.dir[i]);
        }
        i++;
    } while (syscheck.dir[i] != NULL);

#if defined (INOTIFY_ENABLED) || defined (WIN32)
    if (syscheck.realtime && (syscheck.realtime->fd >= 0)) {
        verbose("%s: INFO: Real time file monitoring started.", ARGV0);
    }
#endif
    merror("%s: INFO: Finished creating syscheck database (pre-scan "
           "completed).", ARGV0);
    return (0);
}

