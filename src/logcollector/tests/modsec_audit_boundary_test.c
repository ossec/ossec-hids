/* Minimal unit checks for ModSecurity audit boundary parsing. */
#include <stdio.h>
#include <string.h>
#include <assert.h>

/* Mirror of is_modsec_boundary() in read_modsec_audit.c */
static int is_modsec_boundary(const char *line, char section)
{
    const char *p;

    if (!line || line[0] != '-' || line[1] != '-') {
        return 0;
    }

    p = line + 2;
    while ((*p >= '0' && *p <= '9') ||
           (*p >= 'a' && *p <= 'z') ||
           (*p >= 'A' && *p <= 'Z')) {
        p++;
    }

    if (p[0] != '-' || p[1] != section || p[2] != '-' || p[3] != '-') {
        return 0;
    }

    if (p[4] != '\0' && p[4] != '\r') {
        return 0;
    }

    return 1;
}

int main(void)
{
    assert(is_modsec_boundary("--fbd13fc1-A--", 'A'));
    assert(is_modsec_boundary("--fbd13fc1-Z--", 'Z'));
    assert(is_modsec_boundary("--abc123-H--", 'H'));
    assert(!is_modsec_boundary("--fbd13fc1-A--", 'Z'));
    assert(!is_modsec_boundary("--fbd13fc1-Z-", 'Z'));
    assert(!is_modsec_boundary("-fbd13fc1-Z--", 'Z'));
    assert(!is_modsec_boundary("Message: Access denied", 'Z'));
    assert(is_modsec_boundary("--fbd13fc1-Z--\r", 'Z'));
    printf("modsec_audit_boundary_test: ok\n");
    return 0;
}
