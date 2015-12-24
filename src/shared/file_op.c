/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Functions to handle operation with files
 */

#include "shared.h"

#ifndef WIN32
#include <libgen.h>
#else
#include <aclapi.h>
#endif

/* Vista product information */
#ifdef WIN32
#ifndef PRODUCT_UNLICENSED
#define PRODUCT_UNLICENSED 0xABCDABCD
#endif
#ifndef PRODUCT_UNLICENSED_C
#define PRODUCT_UNLICENSED_C "Product Unlicensed "
#endif

#ifndef PRODUCT_BUSINESS
#define PRODUCT_BUSINESS 0x00000006
#endif
#ifndef PRODUCT_BUSINESS_C
#define PRODUCT_BUSINESS_C "Business Edition "
#endif

#ifndef PRODUCT_BUSINESS_N
#define PRODUCT_BUSINESS_N 0x00000010
#endif
#ifndef PRODUCT_BUSINESS_N_C
#define PRODUCT_BUSINESS_N_C "Business Edition "
#endif

#ifndef PRODUCT_CLUSTER_SERVER
#define PRODUCT_CLUSTER_SERVER 0x00000012
#endif
#ifndef PRODUCT_CLUSTER_SERVER_C
#define PRODUCT_CLUSTER_SERVER_C "Cluster Server Edition "
#endif

#ifndef PRODUCT_DATACENTER_SERVER
#define PRODUCT_DATACENTER_SERVER 0x00000008
#endif
#ifndef PRODUCT_DATACENTER_SERVER_C
#define PRODUCT_DATACENTER_SERVER_C "Datacenter Edition (full) "
#endif

#ifndef PRODUCT_DATACENTER_SERVER_CORE
#define PRODUCT_DATACENTER_SERVER_CORE 0x0000000C
#endif
#ifndef PRODUCT_DATACENTER_SERVER_CORE_C
#define PRODUCT_DATACENTER_SERVER_CORE_C "Datacenter Edition (core) "
#endif

#ifndef PRODUCT_DATACENTER_SERVER_CORE_V
#define PRODUCT_DATACENTER_SERVER_CORE_V 0x00000027
#endif
#ifndef PRODUCT_DATACENTER_SERVER_CORE_V_C
#define PRODUCT_DATACENTER_SERVER_CORE_V_C "Datacenter Edition (core) "
#endif

#ifndef PRODUCT_DATACENTER_SERVER_V
#define PRODUCT_DATACENTER_SERVER_V 0x00000025
#endif
#ifndef PRODUCT_DATACENTER_SERVER_V_C
#define PRODUCT_DATACENTER_SERVER_V_C "Datacenter Edition (full) "
#endif

#ifndef PRODUCT_ENTERPRISE
#define PRODUCT_ENTERPRISE 0x00000004
#endif
#ifndef PRODUCT_ENTERPRISE_C
#define PRODUCT_ENTERPRISE_C "Enterprise Edition "
#endif

#ifndef PRODUCT_ENTERPRISE_N
#define PRODUCT_ENTERPRISE_N 0x0000001B
#endif
#ifndef PRODUCT_ENTERPRISE_N_C
#define PRODUCT_ENTERPRISE_N_C "Enterprise Edition "
#endif

#ifndef PRODUCT_ENTERPRISE_SERVER
#define PRODUCT_ENTERPRISE_SERVER 0x0000000A
#endif
#ifndef PRODUCT_ENTERPRISE_SERVER_C
#define PRODUCT_ENTERPRISE_SERVER_C "Enterprise Edition (full) "
#endif

#ifndef PRODUCT_ENTERPRISE_SERVER_CORE
#define PRODUCT_ENTERPRISE_SERVER_CORE 0x0000000E
#endif
#ifndef PRODUCT_ENTERPRISE_SERVER_CORE_C
#define PRODUCT_ENTERPRISE_SERVER_CORE_C "Enterprise Edition (core) "
#endif

#ifndef PRODUCT_ENTERPRISE_SERVER_CORE_V
#define PRODUCT_ENTERPRISE_SERVER_CORE_V 0x00000029
#endif
#ifndef PRODUCT_ENTERPRISE_SERVER_CORE_V_C
#define PRODUCT_ENTERPRISE_SERVER_CORE_V_C "Enterprise Edition (core) "
#endif

#ifndef PRODUCT_ENTERPRISE_SERVER_IA64
#define PRODUCT_ENTERPRISE_SERVER_IA64 0x0000000F
#endif
#ifndef PRODUCT_ENTERPRISE_SERVER_IA64_C
#define PRODUCT_ENTERPRISE_SERVER_IA64_C "Enterprise Edition for Itanium-based Systems "
#endif

#ifndef PRODUCT_ENTERPRISE_SERVER_V
#define PRODUCT_ENTERPRISE_SERVER_V 0x00000026
#endif
#ifndef PRODUCT_ENTERPRISE_SERVER_V_C
#define PRODUCT_ENTERPRISE_SERVER_V_C "Enterprise Edition (full) "
#endif

#ifndef PRODUCT_HOME_BASIC
#define PRODUCT_HOME_BASIC 0x00000002
#endif
#ifndef PRODUCT_HOME_BASIC_C
#define PRODUCT_HOME_BASIC_C "Home Basic Edition "
#endif

#ifndef PRODUCT_HOME_BASIC_N
#define PRODUCT_HOME_BASIC_N 0x00000005
#endif
#ifndef PRODUCT_HOME_BASIC_N_C
#define PRODUCT_HOME_BASIC_N_C "Home Basic Edition "
#endif

#ifndef PRODUCT_HOME_PREMIUM
#define PRODUCT_HOME_PREMIUM 0x00000003
#endif
#ifndef PRODUCT_HOME_PREMIUM_C
#define PRODUCT_HOME_PREMIUM_C "Home Premium Edition "
#endif

#ifndef PRODUCT_HOME_PREMIUM_N
#define PRODUCT_HOME_PREMIUM_N 0x0000001A
#endif
#ifndef PRODUCT_HOME_PREMIUM_N_C
#define PRODUCT_HOME_PREMIUM_N_C "Home Premium Edition "
#endif

#ifndef PRODUCT_HOME_SERVER
#define PRODUCT_HOME_SERVER 0x00000013
#endif
#ifndef PRODUCT_HOME_SERVER_C
#define PRODUCT_HOME_SERVER_C "Home Server Edition "
#endif

#ifndef PRODUCT_MEDIUMBUSINESS_SERVER_MANAGEMENT
#define PRODUCT_MEDIUMBUSINESS_SERVER_MANAGEMENT 0x0000001E
#endif
#ifndef PRODUCT_MEDIUMBUSINESS_SERVER_MANAGEMENT_C
#define PRODUCT_MEDIUMBUSINESS_SERVER_MANAGEMENT_C "Essential Business Server Management Server "
#endif

#ifndef PRODUCT_MEDIUMBUSINESS_SERVER_MESSAGING
#define PRODUCT_MEDIUMBUSINESS_SERVER_MESSAGING 0x00000020
#endif
#ifndef PRODUCT_MEDIUMBUSINESS_SERVER_MESSAGING_C
#define PRODUCT_MEDIUMBUSINESS_SERVER_MESSAGING_C "Essential Business Server Messaging Server "
#endif

#ifndef PRODUCT_MEDIUMBUSINESS_SERVER_SECURITY
#define PRODUCT_MEDIUMBUSINESS_SERVER_SECURITY 0x0000001F
#endif
#ifndef PRODUCT_MEDIUMBUSINESS_SERVER_SECURITY_C
#define PRODUCT_MEDIUMBUSINESS_SERVER_SECURITY_C "Essential Business Server Security Server "
#endif

#ifndef PRODUCT_SERVER_FOR_SMALLBUSINESS
#define PRODUCT_SERVER_FOR_SMALLBUSINESS 0x00000018
#endif
#ifndef PRODUCT_SERVER_FOR_SMALLBUSINESS_C
#define PRODUCT_SERVER_FOR_SMALLBUSINESS_C "Small Business Edition "
#endif

#ifndef PRODUCT_SMALLBUSINESS_SERVER
#define PRODUCT_SMALLBUSINESS_SERVER 0x00000009
#endif
#ifndef PRODUCT_SMALLBUSINESS_SERVER_C
#define PRODUCT_SMALLBUSINESS_SERVER_C "Small Business Server "
#endif

#ifndef PRODUCT_SMALLBUSINESS_SERVER_PREMIUM
#define PRODUCT_SMALLBUSINESS_SERVER_PREMIUM 0x00000019
#endif
#ifndef PRODUCT_SMALLBUSINESS_SERVER_PREMIUM_C
#define PRODUCT_SMALLBUSINESS_SERVER_PREMIUM_C "Small Business Server Premium Edition "
#endif

#ifndef PRODUCT_STANDARD_SERVER
#define PRODUCT_STANDARD_SERVER 0x00000007
#endif
#ifndef PRODUCT_STANDARD_SERVER_C
#define PRODUCT_STANDARD_SERVER_C "Standard Edition "
#endif

#ifndef PRODUCT_STANDARD_SERVER_CORE
#define PRODUCT_STANDARD_SERVER_CORE 0x0000000D
#endif
#ifndef PRODUCT_STANDARD_SERVER_CORE_C
#define PRODUCT_STANDARD_SERVER_CORE_C "Standard Edition (core) "
#endif

#ifndef PRODUCT_STANDARD_SERVER_CORE_V
#define PRODUCT_STANDARD_SERVER_CORE_V 0x00000028
#endif
#ifndef PRODUCT_STANDARD_SERVER_CORE_V_C
#define PRODUCT_STANDARD_SERVER_CORE_V_C "Standard Edition "
#endif

#ifndef PRODUCT_STANDARD_SERVER_V
#define PRODUCT_STANDARD_SERVER_V 0x00000024
#endif
#ifndef PRODUCT_STANDARD_SERVER_V_C
#define PRODUCT_STANDARD_SERVER_V_C "Standard Edition "
#endif

#ifndef PRODUCT_STARTER
#define PRODUCT_STARTER 0x0000000B
#endif
#ifndef PRODUCT_STARTER_C
#define PRODUCT_STARTER_C "Starter Edition "
#endif

#ifndef PRODUCT_STORAGE_ENTERPRISE_SERVER
#define PRODUCT_STORAGE_ENTERPRISE_SERVER 0x00000017
#endif
#ifndef PRODUCT_STORAGE_ENTERPRISE_SERVER_C
#define PRODUCT_STORAGE_ENTERPRISE_SERVER_C "Storage Server Enterprise Edition "
#endif

#ifndef PRODUCT_STORAGE_EXPRESS_SERVER
#define PRODUCT_STORAGE_EXPRESS_SERVER 0x00000014
#endif
#ifndef PRODUCT_STORAGE_EXPRESS_SERVER_C
#define PRODUCT_STORAGE_EXPRESS_SERVER_C "Storage Server Express Edition "
#endif

#ifndef PRODUCT_STORAGE_STANDARD_SERVER
#define PRODUCT_STORAGE_STANDARD_SERVER 0x00000015
#endif
#ifndef PRODUCT_STORAGE_STANDARD_SERVER_C
#define PRODUCT_STORAGE_STANDARD_SERVER_C "Storage Server Standard Edition "
#endif

#ifndef PRODUCT_STORAGE_WORKGROUP_SERVER
#define PRODUCT_STORAGE_WORKGROUP_SERVER 0x00000016
#endif
#ifndef PRODUCT_STORAGE_WORKGROUP_SERVER_C
#define PRODUCT_STORAGE_WORKGROUP_SERVER_C "Storage Server Workgroup Edition "
#endif

#ifndef PRODUCT_ULTIMATE
#define PRODUCT_ULTIMATE 0x00000001
#endif
#ifndef PRODUCT_ULTIMATE_C
#define PRODUCT_ULTIMATE_C "Ultimate Edition "
#endif

#ifndef PRODUCT_ULTIMATE_N
#define PRODUCT_ULTIMATE_N 0x0000001C
#endif
#ifndef PRODUCT_ULTIMATE_N_C
#define PRODUCT_ULTIMATE_N_C "Ultimate Edition "
#endif

#ifndef PRODUCT_WEB_SERVER
#define PRODUCT_WEB_SERVER 0x00000011
#endif
#ifndef PRODUCT_WEB_SERVER_C
#define PRODUCT_WEB_SERVER_C "Web Server Edition "
#endif

#ifndef PRODUCT_WEB_SERVER_CORE
#define PRODUCT_WEB_SERVER_CORE 0x0000001D
#endif
#ifndef PRODUCT_WEB_SERVER_CORE_C
#define PRODUCT_WEB_SERVER_CORE_C "Web Server Edition "
#endif
#endif /* WIN32 */

const char *__local_name = "unset";


/* Set the name of the starting program */
void OS_SetName(const char *name)
{
    __local_name = name;
    return;
}

time_t File_DateofChange(const char *file)
{
    struct stat file_status;

    if (stat(file, &file_status) < 0) {
        return (-1);
    }

    return (file_status.st_mtime);
}

int IsDir(const char *file)
{
    struct stat file_status;
    if (stat(file, &file_status) < 0) {
        return (-1);
    }
    if (S_ISDIR(file_status.st_mode)) {
        return (0);
    }
    return (-1);
}

int CreatePID(const char *name, int pid)
{
    char file[256];
    FILE *fp;

    if (isChroot()) {
        snprintf(file, 255, "%s/%s-%d.pid", OS_PIDFILE, name, pid);
    } else {
        snprintf(file, 255, "%s%s/%s-%d.pid", DEFAULTDIR,
                 OS_PIDFILE, name, pid);
    }

    fp = fopen(file, "a");
    if (!fp) {
        return (-1);
    }

    fprintf(fp, "%d\n", pid);

    if (chmod(file, 0640) != 0) {
        fclose(fp);
        return (-1);
    }

    fclose(fp);

    return (0);
}

int DeletePID(const char *name)
{
    char file[256];

    if (isChroot()) {
        snprintf(file, 255, "%s/%s-%d.pid", OS_PIDFILE, name, (int)getpid());
    } else {
        snprintf(file, 255, "%s%s/%s-%d.pid", DEFAULTDIR,
                 OS_PIDFILE, name, (int)getpid());
    }

    if (File_DateofChange(file) < 0) {
        return (-1);
    }

    if (unlink(file)) {
        log2file(
            DELETE_ERROR,
            __local_name,
            file,
            errno,
            strerror(errno)
        );
    }

    return (0);
}

int UnmergeFiles(const char *finalpath, const char *optdir)
{
    int ret = 1;
    size_t i = 0, n = 0, files_size = 0;
    char *files;
    char final_name[2048 + 1];
    char buf[2048 + 1];
    FILE *fp;
    FILE *finalfp;

    finalfp = fopen(finalpath, "r");
    if (!finalfp) {
        merror("%s: ERROR: Unable to read merged file: '%s'.",
               __local_name, finalpath);
        return (0);
    }

    while (1) {
        /* Read header portion */
        if (fgets(buf, sizeof(buf) - 1, finalfp) == NULL) {
            break;
        }

        /* Initiator */
        if (buf[0] != '!') {
            continue;
        }

        /* Get file size and name */
        files_size = (size_t) atol(buf + 1);

        files = strchr(buf, '\n');
        if (files) {
            *files = '\0';
        }

        files = strchr(buf, ' ');
        if (!files) {
            ret = 0;
            continue;
        }
        files++;

        if (optdir) {
            snprintf(final_name, 2048, "%s/%s", optdir, files);
        } else {
            strncpy(final_name, files, 2048);
            final_name[2048] = '\0';
        }

        /* Open filename */
        fp = fopen(final_name, "w");
        if (!fp) {
            ret = 0;
            merror("%s: ERROR: Unable to unmerge file '%s'.",
                   __local_name, final_name);
        }

        if (files_size < sizeof(buf) - 1) {
            i = files_size;
            files_size = 0;
        } else {
            i = sizeof(buf) - 1;
            files_size -= sizeof(buf) - 1;
        }

        while ((n = fread(buf, 1, i, finalfp)) > 0) {
            buf[n] = '\0';

            if (fp) {
                fwrite(buf, n, 1, fp);
            }

            if (files_size == 0) {
                break;
            } else {
                if (files_size < sizeof(buf) - 1) {
                    i = files_size;
                    files_size = 0;
                } else {
                    i = sizeof(buf) - 1;
                    files_size -= sizeof(buf) - 1;
                }
            }
        }

        if (fp) {
            fclose(fp);
        }
    }

    fclose(finalfp);
    return (ret);
}

int MergeAppendFile(const char *finalpath, const char *files)
{
    size_t n = 0;
    long files_size = 0;
    char buf[2048 + 1];
    const char *tmpfile;
    FILE *fp;
    FILE *finalfp;

    /* Create a new entry */
    if (files == NULL) {
        finalfp = fopen(finalpath, "w");
        if (!finalfp) {
            merror("%s: ERROR: Unable to create merged file: '%s'.",
                   __local_name, finalpath);
            return (0);
        }
        fclose(finalfp);

        return (1);
    }

    finalfp = fopen(finalpath, "a");
    if (!finalfp) {
        merror("%s: ERROR: Unable to append merged file: '%s'.",
               __local_name, finalpath);
        return (0);
    }

    fp = fopen(files, "r");
    if (!fp) {
        merror("%s: ERROR: Unable to merge file '%s'.", __local_name, files);
        fclose(finalfp);
        return (0);
    }

    fseek(fp, 0, SEEK_END);
    files_size = ftell(fp);

    tmpfile = strrchr(files, '/');
    if (tmpfile) {
        tmpfile++;
    } else {
        tmpfile = files;
    }
    fprintf(finalfp, "!%ld %s\n", files_size, tmpfile);

    fseek(fp, 0, SEEK_SET);

    while ((n = fread(buf, 1, sizeof(buf) - 1, fp)) > 0) {
        buf[n] = '\0';
        fwrite(buf, n, 1, finalfp);
    }

    fclose(fp);

    fclose(finalfp);
    return (1);
}

int MergeFiles(const char *finalpath, char **files)
{
    int i = 0, ret = 1;
    size_t n = 0;
    long files_size = 0;

    char *tmpfile;
    char buf[2048 + 1];
    FILE *fp;
    FILE *finalfp;

    finalfp = fopen(finalpath, "w");
    if (!finalfp) {
        merror("%s: ERROR: Unable to create merged file: '%s'.",
               __local_name, finalpath);
        return (0);
    }

    while (files[i]) {
        fp = fopen(files[i], "r");
        if (!fp) {
            merror("%s: ERROR: Unable to merge file '%s'.", __local_name, files[i]);
            i++;
            ret = 0;
            continue;
        }

        fseek(fp, 0, SEEK_END);
        files_size = ftell(fp);

        /* Remove last entry */
        tmpfile = strrchr(files[i], '/');
        if (tmpfile) {
            tmpfile++;
        } else {
            tmpfile = files[i];
        }

        fprintf(finalfp, "!%ld %s\n", files_size, tmpfile);

        fseek(fp, 0, SEEK_SET);
        while ((n = fread(buf, 1, sizeof(buf) - 1, fp)) > 0) {
            buf[n] = '\0';
            fwrite(buf, n, 1, finalfp);
        }

        fclose(fp);
        i++;
    }

    fclose(finalfp);
    return (ret);
}


#ifndef WIN32
/* Get basename of path */
char *basename_ex(char *path)
{
    return (basename(path));
}

/* Rename file or directory */
int rename_ex(const char *source, const char *destination)
{
    if (rename(source, destination)) {
        log2file(
            RENAME_ERROR,
            __local_name,
            source,
            destination,
            errno,
            strerror(errno)
        );

        return (-1);
    }

    return (0);
}

/* Create a temporary file */
int mkstemp_ex(char *tmp_path)
{
    int fd;

    fd = mkstemp(tmp_path);

    if (fd == -1) {
        log2file(
            MKSTEMP_ERROR,
            __local_name,
            tmp_path,
            errno,
            strerror(errno)
        );

        return (-1);
    }

    /* mkstemp() only implicitly does this in POSIX 2008 */
    if (fchmod(fd, 0600) == -1) {
        close(fd);

        log2file(
            CHMOD_ERROR,
            __local_name,
            tmp_path,
            errno,
            strerror(errno)
        );

        if (unlink(tmp_path)) {
            log2file(
                DELETE_ERROR,
                __local_name,
                tmp_path,
                errno,
                strerror(errno)
            );
        }

        return (-1);
    }

    close(fd);
    return (0);
}


/* Get uname. Memory must be freed after use */
char *getuname()
{
    struct utsname uts_buf;

    if (uname(&uts_buf) >= 0) {
        char *ret;

        ret = (char *) calloc(256, sizeof(char));
        if (ret == NULL) {
            return (NULL);
        }

        snprintf(ret, 255, "%s %s %s %s %s - %s %s",
                 uts_buf.sysname,
                 uts_buf.nodename,
                 uts_buf.release,
                 uts_buf.version,
                 uts_buf.machine,
                 __ossec_name, __version);

        return (ret);
    } else {
        char *ret;
        ret = (char *) calloc(256, sizeof(char));
        if (ret == NULL) {
            return (NULL);
        }

        snprintf(ret, 255, "No system info available -  %s %s",
                 __ossec_name, __version);

        return (ret);
    }

    return (NULL);
}

/* Daemonize a process without closing stdin/stdout/stderr */
void goDaemonLight()
{
    pid_t pid;

    pid = fork();

    if (pid < 0) {
        merror(FORK_ERROR, __local_name, errno, strerror(errno));
        return;
    } else if (pid) {
        exit(0);
    }

    /* Become session leader */
    if (setsid() < 0) {
        merror(SETSID_ERROR, __local_name, errno, strerror(errno));
        return;
    }

    /* Fork again */
    pid = fork();
    if (pid < 0) {
        merror(FORK_ERROR, __local_name, errno, strerror(errno));
        return;
    } else if (pid) {
        exit(0);
    }

    dup2(1, 2);

    /* Go to / */
    if (chdir("/") == -1) {
        merror(CHDIR_ERROR, __local_name, "/", errno, strerror(errno));
    }

    return;
}

/* Daemonize a process */
void goDaemon()
{
    int fd;
    pid_t pid;

    pid = fork();
    if (pid < 0) {
        merror(FORK_ERROR, __local_name, errno, strerror(errno));
        return;
    } else if (pid) {
        exit(0);
    }

    /* Become session leader */
    if (setsid() < 0) {
        merror(SETSID_ERROR, __local_name, errno, strerror(errno));
        return;
    }

    /* Fork again */
    pid = fork();
    if (pid < 0) {
        merror(FORK_ERROR, __local_name, errno, strerror(errno));
        return;
    } else if (pid) {
        exit(0);
    }

    /* Dup stdin, stdout and stderr to /dev/null */
    if ((fd = open("/dev/null", O_RDWR)) >= 0) {
        dup2(fd, 0);
        dup2(fd, 1);
        dup2(fd, 2);

        close(fd);
    }

    /* Go to / */
    if (chdir("/") == -1) {
        merror(CHDIR_ERROR, __local_name, "/", errno, strerror(errno));
    }

    return;
}

#else /* WIN32 */

int checkVista()
{
    char *m_uname;
    isVista = 0;

    m_uname = getuname();
    if (!m_uname) {
        merror(MEM_ERROR, __local_name, errno, strerror(errno));
        return (0);
    }

    /* Check if the system is Vista (must be called during the startup) */
    if (strstr(m_uname, "Windows Server 2008") ||
            strstr(m_uname, "Vista") ||
            strstr(m_uname, "Windows 7") ||
            strstr(m_uname, "Windows 8") ||
            strstr(m_uname, "Windows Server 2012")) {
        isVista = 1;
        verbose("%s: INFO: System is Vista or newer (%s).",
                __local_name, m_uname);
    } else {
        verbose("%s: INFO: System is older than Vista (%s).",
                __local_name, m_uname);
    }

    free(m_uname);

    return (isVista);
}

/* Get basename of path */
char *basename_ex(char *path)
{
    return (PathFindFileNameA(path));
}

/* Rename file or directory */
int rename_ex(const char *source, const char *destination)
{
    if (!MoveFileEx(source, destination, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        log2file(
            "%s: ERROR: Could not move (%s) to (%s) which returned (%lu)",
            __local_name,
            source,
            destination,
            GetLastError()
        );

        return (-1);
    }

    return (0);
}

/* Create a temporary file */
int mkstemp_ex(char *tmp_path)
{
    DWORD dwResult;
    int result;
    int status = -1;

    HANDLE h = NULL;
    PACL pACL = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    EXPLICIT_ACCESS ea[2];
    SECURITY_ATTRIBUTES sa;

    PSID pAdminGroupSID = NULL;
    PSID pSystemGroupSID = NULL;
    SID_IDENTIFIER_AUTHORITY SIDAuthNT = {SECURITY_NT_AUTHORITY};

#if defined(_MSC_VER) && _MSC_VER >= 1500
    result = _mktemp_s(tmp_path, strlen(tmp_path) + 1);

    if (result != 0) {
        log2file(
            "%s: ERROR: Could not create temporary file (%s) which returned (%d)",
            __local_name,
            tmp_path,
            result
        );

        return (-1);
    }
#else
    if (_mktemp(tmp_path) == NULL) {
        log2file(
            "%s: ERROR: Could not create temporary file (%s) which returned [(%d)-(%s)]",
            __local_name,
            tmp_path,
            errno,
            strerror(errno)
        );

        return (-1);
    }
#endif

    /* Create SID for the BUILTIN\Administrators group */
    result = AllocateAndInitializeSid(
                 &SIDAuthNT,
                 2,
                 SECURITY_BUILTIN_DOMAIN_RID,
                 DOMAIN_ALIAS_RID_ADMINS,
                 0, 0, 0, 0, 0, 0,
                 &pAdminGroupSID
             );

    if (!result) {
        log2file(
            "%s: ERROR: Could not create BUILTIN\\Administrators group SID which returned (%lu)",
            __local_name,
            GetLastError()
        );

        goto cleanup;
    }

    /* Create SID for the SYSTEM group */
    result = AllocateAndInitializeSid(
                 &SIDAuthNT,
                 1,
                 SECURITY_LOCAL_SYSTEM_RID,
                 0, 0, 0, 0, 0, 0, 0,
                 &pSystemGroupSID
             );

    if (!result) {
        log2file(
            "%s: ERROR: Could not create SYSTEM group SID which returned (%lu)",
            __local_name,
            GetLastError()
        );

        goto cleanup;
    }

    /* Initialize an EXPLICIT_ACCESS structure for an ACE */
    ZeroMemory(&ea, 2 * sizeof(EXPLICIT_ACCESS));

    /* Add Administrators group */
    ea[0].grfAccessPermissions = GENERIC_ALL;
    ea[0].grfAccessMode = SET_ACCESS;
    ea[0].grfInheritance = NO_INHERITANCE;
    ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[0].Trustee.ptstrName = (LPTSTR)pAdminGroupSID;

    /* Add SYSTEM group */
    ea[1].grfAccessPermissions = GENERIC_ALL;
    ea[1].grfAccessMode = SET_ACCESS;
    ea[1].grfInheritance = NO_INHERITANCE;
    ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[1].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[1].Trustee.ptstrName = (LPTSTR)pSystemGroupSID;

    /* Set entries in ACL */
    dwResult = SetEntriesInAcl(2, ea, NULL, &pACL);

    if (dwResult != ERROR_SUCCESS) {
        log2file(
            "%s: ERROR: Could not set ACL entries which returned (%lu)",
            __local_name,
            dwResult
        );

        goto cleanup;
    }

    /* Initialize security descriptor */
    pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(
              LPTR,
              SECURITY_DESCRIPTOR_MIN_LENGTH
          );

    if (pSD == NULL) {
        log2file(
            "%s: ERROR: Could not initalize SECURITY_DESCRIPTOR because of a LocalAlloc() failure which returned (%lu)",
            __local_name,
            GetLastError()
        );

        goto cleanup;
    }

    if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION)) {
        log2file(
            "%s: ERROR: Could not initalize SECURITY_DESCRIPTOR because of an InitializeSecurityDescriptor() failure which returned (%lu)",
            __local_name,
            GetLastError()
        );

        goto cleanup;
    }

    /* Set owner */
    if (!SetSecurityDescriptorOwner(pSD, NULL, FALSE)) {
        log2file(
            "%s: ERROR: Could not set owner which returned (%lu)",
            __local_name,
            GetLastError()
        );

        goto cleanup;
    }

    /* Set group owner */
    if (!SetSecurityDescriptorGroup(pSD, NULL, FALSE)) {
        log2file(
            "%s: ERROR: Could not set group owner which returned (%lu)",
            __local_name,
            GetLastError()
        );

        goto cleanup;
    }

    /* Add ACL to security descriptor */
    if (!SetSecurityDescriptorDacl(pSD, TRUE, pACL, FALSE)) {
        log2file(
            "%s: ERROR: Could not set SECURITY_DESCRIPTOR DACL which returned (%lu)",
            __local_name,
            GetLastError()
        );

        goto cleanup;
    }

    /* Initialize security attributes structure */
    sa.nLength = sizeof (SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = pSD;
    sa.bInheritHandle = FALSE;

    h = CreateFileA(
            tmp_path,
            GENERIC_WRITE,
            0,
            &sa,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );

    if (h == INVALID_HANDLE_VALUE) {
        log2file(
            "%s: ERROR: Could not create temporary file (%s) which returned (%lu)",
            __local_name,
            tmp_path,
            GetLastError()
        );

        goto cleanup;
    }

    if (!CloseHandle(h)) {
        log2file(
            "%s: ERROR: Could not close file handle to (%s) which returned (%lu)",
            __local_name,
            tmp_path,
            GetLastError()
        );

        goto cleanup;
    }

    /* Success */
    status = 0;

cleanup:
    if (pAdminGroupSID) {
        FreeSid(pAdminGroupSID);
    }

    if (pSystemGroupSID) {
        FreeSid(pSystemGroupSID);
    }

    if (pACL) {
        LocalFree(pACL);
    }

    if (pSD) {
        LocalFree(pSD);
    }

    return (status);
}

/* Get uname for Windows */
char *getuname()
{
    int ret_size = OS_SIZE_1024 - 2;
    char *ret = NULL;
    char os_v[128 + 1];

    typedef void (WINAPI * PGNSI)(LPSYSTEM_INFO);
    typedef BOOL (WINAPI * PGPI)(DWORD, DWORD, DWORD, DWORD, PDWORD);

    /* See http://msdn.microsoft.com/en-us/library/windows/desktop/ms724429%28v=vs.85%29.aspx */
    OSVERSIONINFOEX osvi;
    SYSTEM_INFO si;
    PGNSI pGNSI;
    PGPI pGPI;
    BOOL bOsVersionInfoEx;
    DWORD dwType;

    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

    if (!(bOsVersionInfoEx = GetVersionEx ((OSVERSIONINFO *) &osvi))) {
        osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
        if (!GetVersionEx((OSVERSIONINFO *)&osvi)) {
            return (NULL);
        }
    }

    /* Allocate memory */
    os_calloc(OS_SIZE_1024 + 1, sizeof(char), ret);
    ret[OS_SIZE_1024] = '\0';

    switch (osvi.dwPlatformId) {
        /* Test for the Windows NT product family */
        case VER_PLATFORM_WIN32_NT:
            if (osvi.dwMajorVersion == 6) {
                if (osvi.dwMinorVersion == 0) {
                    if (osvi.wProductType == VER_NT_WORKSTATION ) {
                        strncat(ret, "Microsoft Windows Vista ", ret_size - 1);
                    } else {
                        strncat(ret, "Microsoft Windows Server 2008 ", ret_size - 1);
                    }
                } else if (osvi.dwMinorVersion == 1) {
                    if (osvi.wProductType == VER_NT_WORKSTATION ) {
                        strncat(ret, "Microsoft Windows 7 ", ret_size - 1);
                    } else {
                        strncat(ret, "Microsoft Windows Server 2008 R2 ", ret_size - 1);
                    }
                } else if (osvi.dwMinorVersion == 2) {
                    if (osvi.wProductType == VER_NT_WORKSTATION ) {
                        strncat(ret, "Microsoft Windows 8 ", ret_size - 1);
                    } else {
                        strncat(ret, "Microsoft Windows Server 2012 ", ret_size - 1);
                    }
                } else if (osvi.dwMinorVersion == 3) {
                    if (osvi.wProductType == VER_NT_WORKSTATION ) {
                        strncat(ret, "Microsoft Windows 8.1 ", ret_size - 1);
                    } else {
                        strncat(ret, "Microsoft Windows Server 2012 R2 ", ret_size - 1);
                    }
                }

                ret_size -= strlen(ret) + 1;


                /* Get product version */
                pGPI = (PGPI) GetProcAddress(
                           GetModuleHandle(TEXT("kernel32.dll")),
                           "GetProductInfo");

                pGPI( 6, 0, 0, 0, &dwType);

                switch (dwType) {
                    case PRODUCT_UNLICENSED:
                        strncat(ret, PRODUCT_UNLICENSED_C, ret_size - 1);
                        break;
                    case PRODUCT_BUSINESS:
                        strncat(ret, PRODUCT_BUSINESS_C, ret_size - 1);
                        break;
                    case PRODUCT_BUSINESS_N:
                        strncat(ret, PRODUCT_BUSINESS_N_C, ret_size - 1);
                        break;
                    case PRODUCT_CLUSTER_SERVER:
                        strncat(ret, PRODUCT_CLUSTER_SERVER_C, ret_size - 1);
                        break;
                    case PRODUCT_DATACENTER_SERVER:
                        strncat(ret, PRODUCT_DATACENTER_SERVER_C, ret_size - 1);
                        break;
                    case PRODUCT_DATACENTER_SERVER_CORE:
                        strncat(ret, PRODUCT_DATACENTER_SERVER_CORE_C, ret_size - 1);
                        break;
                    case PRODUCT_DATACENTER_SERVER_CORE_V:
                        strncat(ret, PRODUCT_DATACENTER_SERVER_CORE_V_C, ret_size - 1);
                        break;
                    case PRODUCT_DATACENTER_SERVER_V:
                        strncat(ret, PRODUCT_DATACENTER_SERVER_V_C, ret_size - 1);
                        break;
                    case PRODUCT_ENTERPRISE:
                        strncat(ret, PRODUCT_ENTERPRISE_C, ret_size - 1);
                        break;
                    case PRODUCT_ENTERPRISE_N:
                        strncat(ret, PRODUCT_ENTERPRISE_N_C, ret_size - 1);
                        break;
                    case PRODUCT_ENTERPRISE_SERVER:
                        strncat(ret, PRODUCT_ENTERPRISE_SERVER_C, ret_size - 1);
                        break;
                    case PRODUCT_ENTERPRISE_SERVER_CORE:
                        strncat(ret, PRODUCT_ENTERPRISE_SERVER_CORE_C, ret_size - 1);
                        break;
                    case PRODUCT_ENTERPRISE_SERVER_CORE_V:
                        strncat(ret, PRODUCT_ENTERPRISE_SERVER_CORE_V_C, ret_size - 1);
                        break;
                    case PRODUCT_ENTERPRISE_SERVER_IA64:
                        strncat(ret, PRODUCT_ENTERPRISE_SERVER_IA64_C, ret_size - 1);
                        break;
                    case PRODUCT_ENTERPRISE_SERVER_V:
                        strncat(ret, PRODUCT_ENTERPRISE_SERVER_V_C, ret_size - 1);
                        break;
                    case PRODUCT_HOME_BASIC:
                        strncat(ret, PRODUCT_HOME_BASIC_C, ret_size - 1);
                        break;
                    case PRODUCT_HOME_BASIC_N:
                        strncat(ret, PRODUCT_HOME_BASIC_N_C, ret_size - 1);
                        break;
                    case PRODUCT_HOME_PREMIUM:
                        strncat(ret, PRODUCT_HOME_PREMIUM_C, ret_size - 1);
                        break;
                    case PRODUCT_HOME_PREMIUM_N:
                        strncat(ret, PRODUCT_HOME_PREMIUM_N_C, ret_size - 1);
                        break;
                    case PRODUCT_HOME_SERVER:
                        strncat(ret, PRODUCT_HOME_SERVER_C, ret_size - 1);
                        break;
                    case PRODUCT_MEDIUMBUSINESS_SERVER_MANAGEMENT:
                        strncat(ret, PRODUCT_MEDIUMBUSINESS_SERVER_MANAGEMENT_C, ret_size - 1);
                        break;
                    case PRODUCT_MEDIUMBUSINESS_SERVER_MESSAGING:
                        strncat(ret, PRODUCT_MEDIUMBUSINESS_SERVER_MESSAGING_C, ret_size - 1);
                        break;
                    case PRODUCT_MEDIUMBUSINESS_SERVER_SECURITY:
                        strncat(ret, PRODUCT_MEDIUMBUSINESS_SERVER_SECURITY_C, ret_size - 1);
                        break;
                    case PRODUCT_SERVER_FOR_SMALLBUSINESS:
                        strncat(ret, PRODUCT_SERVER_FOR_SMALLBUSINESS_C, ret_size - 1);
                        break;
                    case PRODUCT_SMALLBUSINESS_SERVER:
                        strncat(ret, PRODUCT_SMALLBUSINESS_SERVER_C, ret_size - 1);
                        break;
                    case PRODUCT_SMALLBUSINESS_SERVER_PREMIUM:
                        strncat(ret, PRODUCT_SMALLBUSINESS_SERVER_PREMIUM_C, ret_size - 1);
                        break;
                    case PRODUCT_STANDARD_SERVER:
                        strncat(ret, PRODUCT_STANDARD_SERVER_C, ret_size - 1);
                        break;
                    case PRODUCT_STANDARD_SERVER_CORE:
                        strncat(ret, PRODUCT_STANDARD_SERVER_CORE_C, ret_size - 1);
                        break;
                    case PRODUCT_STANDARD_SERVER_CORE_V:
                        strncat(ret, PRODUCT_STANDARD_SERVER_CORE_V_C, ret_size - 1);
                        break;
                    case PRODUCT_STANDARD_SERVER_V:
                        strncat(ret, PRODUCT_STANDARD_SERVER_V_C, ret_size - 1);
                        break;
                    case PRODUCT_STARTER:
                        strncat(ret, PRODUCT_STARTER_C, ret_size - 1);
                        break;
                    case PRODUCT_STORAGE_ENTERPRISE_SERVER:
                        strncat(ret, PRODUCT_STORAGE_ENTERPRISE_SERVER_C, ret_size - 1);
                        break;
                    case PRODUCT_STORAGE_EXPRESS_SERVER:
                        strncat(ret, PRODUCT_STORAGE_EXPRESS_SERVER_C, ret_size - 1);
                        break;
                    case PRODUCT_STORAGE_STANDARD_SERVER:
                        strncat(ret, PRODUCT_STORAGE_STANDARD_SERVER_C, ret_size - 1);
                        break;
                    case PRODUCT_STORAGE_WORKGROUP_SERVER:
                        strncat(ret, PRODUCT_STORAGE_WORKGROUP_SERVER_C, ret_size - 1);
                        break;
                    case PRODUCT_ULTIMATE:
                        strncat(ret, PRODUCT_ULTIMATE_C, ret_size - 1);
                        break;
                    case PRODUCT_ULTIMATE_N:
                        strncat(ret, PRODUCT_ULTIMATE_N_C, ret_size - 1);
                        break;
                    case PRODUCT_WEB_SERVER:
                        strncat(ret, PRODUCT_WEB_SERVER_C, ret_size - 1);
                        break;
                    case PRODUCT_WEB_SERVER_CORE:
                        strncat(ret, PRODUCT_WEB_SERVER_CORE_C, ret_size - 1);
                        break;
                }

                ret_size -= strlen(ret) + 1;
            } else if (osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 2) {
                pGNSI = (PGNSI) GetProcAddress(
                            GetModuleHandle("kernel32.dll"),
                            "GetNativeSystemInfo");
                if (NULL != pGNSI) {
                    pGNSI(&si);
                }

                if ( GetSystemMetrics(89) )
                    strncat(ret, "Microsoft Windows Server 2003 R2 ",
                            ret_size - 1);
                else if (osvi.wProductType == VER_NT_WORKSTATION &&
                         si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
                    strncat(ret,
                            "Microsoft Windows XP Professional x64 Edition ",
                            ret_size - 1 );
                } else {
                    strncat(ret, "Microsoft Windows Server 2003, ", ret_size - 1);
                }

                ret_size -= strlen(ret) + 1;
            } else if (osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 1) {
                strncat(ret, "Microsoft Windows XP ", ret_size - 1);

                ret_size -= strlen(ret) + 1;
            } else if (osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 0) {
                strncat(ret, "Microsoft Windows 2000 ", ret_size - 1);

                ret_size -= strlen(ret) + 1;
            } else if (osvi.dwMajorVersion <= 4) {
                strncat(ret, "Microsoft Windows NT ", ret_size - 1);

                ret_size -= strlen(ret) + 1;
            } else {
                strncat(ret, "Microsoft Windows Unknown ", ret_size - 1);

                ret_size -= strlen(ret) + 1;
            }

            /* Test for specific product on Windows NT 4.0 SP6 and later */
            if (bOsVersionInfoEx) {
                /* Test for the workstation type */
                if (osvi.wProductType == VER_NT_WORKSTATION &&
                        si.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64) {
                    if ( osvi.dwMajorVersion == 4 ) {
                        strncat(ret, "Workstation 4.0 ", ret_size - 1);
                    } else if ( osvi.wSuiteMask & VER_SUITE_PERSONAL ) {
                        strncat(ret, "Home Edition ", ret_size - 1);
                    } else {
                        strncat(ret, "Professional ", ret_size - 1);
                    }

                    /* Fix size */
                    ret_size -= strlen(ret) + 1;
                }

                /* Test for the server type */
                else if ( osvi.wProductType == VER_NT_SERVER ||
                          osvi.wProductType == VER_NT_DOMAIN_CONTROLLER ) {
                    if (osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 2) {
                        if (si.wProcessorArchitecture ==
                                PROCESSOR_ARCHITECTURE_IA64 ) {
                            if ( osvi.wSuiteMask & VER_SUITE_DATACENTER )
                                strncat(ret,
                                        "Datacenter Edition for Itanium-based Systems ",
                                        ret_size - 1);
                            else if ( osvi.wSuiteMask & VER_SUITE_ENTERPRISE )
                                strncat(ret,
                                        "Enterprise Edition for Itanium-based Systems ",
                                        ret_size - 1);

                            ret_size -= strlen(ret) + 1;
                        } else if ( si.wProcessorArchitecture ==
                                    PROCESSOR_ARCHITECTURE_AMD64 ) {
                            if ( osvi.wSuiteMask & VER_SUITE_DATACENTER )
                                strncat(ret, "Datacenter x64 Edition ",
                                        ret_size - 1 );
                            else if ( osvi.wSuiteMask & VER_SUITE_ENTERPRISE )
                                strncat(ret, "Enterprise x64 Edition ",
                                        ret_size - 1 );
                            else
                                strncat(ret, "Standard x64 Edition ",
                                        ret_size - 1 );

                            ret_size -= strlen(ret) + 1;
                        } else {
                            if ( osvi.wSuiteMask & VER_SUITE_DATACENTER )
                                strncat(ret, "Datacenter Edition ",
                                        ret_size - 1 );
                            else if ( osvi.wSuiteMask & VER_SUITE_ENTERPRISE ) {
                                strncat(ret, "Enterprise Edition ", ret_size - 1);
                            } else if ( osvi.wSuiteMask == VER_SUITE_BLADE ) {
                                strncat(ret, "Web Edition ", ret_size - 1 );
                            } else {
                                strncat(ret, "Standard Edition ", ret_size - 1);
                            }

                            ret_size -= strlen(ret) + 1;
                        }
                    } else if (osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 0) {
                        if ( osvi.wSuiteMask & VER_SUITE_DATACENTER ) {
                            strncat(ret, "Datacenter Server ", ret_size - 1);
                        } else if ( osvi.wSuiteMask & VER_SUITE_ENTERPRISE ) {
                            strncat(ret, "Advanced Server ", ret_size - 1 );
                        } else {
                            strncat(ret, "Server ", ret_size - 1);
                        }

                        ret_size -= strlen(ret) + 1;
                    } else if (osvi.dwMajorVersion <= 4) { /* Windows NT 4.0 */
                        if ( osvi.wSuiteMask & VER_SUITE_ENTERPRISE )
                            strncat(ret, "Server 4.0, Enterprise Edition ",
                                    ret_size - 1 );
                        else {
                            strncat(ret, "Server 4.0 ", ret_size - 1);
                        }

                        ret_size -= strlen(ret) + 1;
                    }
                }
            }
            /* Test for specific product on Windows NT 4.0 SP5 and earlier */
            else {
                HKEY hKey;
                char szProductType[81];
                DWORD dwBufLen = 80;
                LONG lRet;

                lRet = RegOpenKeyEx( HKEY_LOCAL_MACHINE,
                                     "SYSTEM\\CurrentControlSet\\Control\\ProductOptions",
                                     0, KEY_QUERY_VALUE, &hKey );
                if (lRet == ERROR_SUCCESS) {
                    char __wv[32];

                    lRet = RegQueryValueEx( hKey, "ProductType", NULL, NULL,
                                            (LPBYTE) szProductType, &dwBufLen);
                    RegCloseKey( hKey );

                    if ((lRet == ERROR_SUCCESS) && (dwBufLen < 80) ) {
                        if (lstrcmpi( "WINNT", szProductType) == 0 ) {
                            strncat(ret, "Workstation ", ret_size - 1);
                        } else if (lstrcmpi( "LANMANNT", szProductType) == 0 ) {
                            strncat(ret, "Server ", ret_size - 1);
                        } else if (lstrcmpi( "SERVERNT", szProductType) == 0 ) {
                            strncat(ret, "Advanced Server " , ret_size - 1);
                        }

                        ret_size -= strlen(ret) + 1;

                        memset(__wv, '\0', 32);
                        snprintf(__wv, 31,
                                 "%d.%d ",
                                 (int)osvi.dwMajorVersion,
                                 (int)osvi.dwMinorVersion);

                        strncat(ret, __wv, ret_size - 1);
                        ret_size -= strlen(__wv) + 1;
                    }
                }
            }

            /* Display service pack (if any) and build number */
            if ( osvi.dwMajorVersion == 4 &&
                    lstrcmpi( osvi.szCSDVersion, "Service Pack 6" ) == 0 ) {
                HKEY hKey;
                LONG lRet;
                char __wp[64];

                memset(__wp, '\0', 64);
                /* Test for SP6 versus SP6a */
                lRet = RegOpenKeyEx( HKEY_LOCAL_MACHINE,
                                     "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Hotfix\\Q246009",
                                     0, KEY_QUERY_VALUE, &hKey );
                if ( lRet == ERROR_SUCCESS )
                    snprintf(__wp, 63, "Service Pack 6a (Build %d)",
                             (int)osvi.dwBuildNumber & 0xFFFF );
                else { /* Windows NT 4.0 prior to SP6a */
                    snprintf(__wp, 63, "%s (Build %d)",
                             osvi.szCSDVersion,
                             (int)osvi.dwBuildNumber & 0xFFFF);
                }

                strncat(ret, __wp, ret_size - 1);
                ret_size -= strlen(__wp) + 1;
                RegCloseKey( hKey );
            } else {
                char __wp[64];

                memset(__wp, '\0', 64);

                snprintf(__wp, 63, "%s (Build %d)",
                         osvi.szCSDVersion,
                         (int)osvi.dwBuildNumber & 0xFFFF);

                strncat(ret, __wp, ret_size - 1);
                ret_size -= strlen(__wp) + 1;
            }
            break;

        /* Test for Windows Me/98/95 */
        case VER_PLATFORM_WIN32_WINDOWS:
            if (osvi.dwMajorVersion == 4 && osvi.dwMinorVersion == 0) {
                strncat(ret, "Microsoft Windows 95 ", ret_size - 1);
                ret_size -= strlen(ret) + 1;
            }

            if (osvi.dwMajorVersion == 4 && osvi.dwMinorVersion == 10) {
                strncat(ret, "Microsoft Windows 98 ", ret_size - 1);
                ret_size -= strlen(ret) + 1;
            }

            if (osvi.dwMajorVersion == 4 && osvi.dwMinorVersion == 90) {
                strncat(ret, "Microsoft Windows Millennium Edition",
                        ret_size - 1);

                ret_size -= strlen(ret) + 1;
            }
            break;

        case VER_PLATFORM_WIN32s:
            strncat(ret, "Microsoft Win32s", ret_size - 1);
            ret_size -= strlen(ret) + 1;
            break;
    }

    /* Add OSSEC-HIDS version */
    snprintf(os_v, 128, " - %s %s", __ossec_name, __version);
    strncat(ret, os_v, ret_size - 1);

    return (ret);

}

#endif /* WIN32 */
