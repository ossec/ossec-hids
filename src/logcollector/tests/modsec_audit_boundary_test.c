/* Unit checks for ModSecurity audit boundary parsing / ID binding. */
#include <stdio.h>
#include <string.h>
#include <assert.h>

#define MODSEC_ID_MAX 64

static int parse_modsec_boundary(const char *line, char *id_out, size_t id_cap,
                                 size_t *id_len_out, char *section_out)
{
    const char *p;
    size_t id_len = 0;

    if (!line || !id_out || !section_out || id_cap < 2) {
        return 0;
    }

    if (line[0] != '-' || line[1] != '-') {
        return 0;
    }

    p = line + 2;
    while (((*p >= '0' && *p <= '9') ||
            (*p >= 'a' && *p <= 'z') ||
            (*p >= 'A' && *p <= 'Z')) &&
           id_len + 1 < id_cap) {
        id_out[id_len++] = *p++;
    }

    if (id_len == 0) {
        return 0;
    }
    if ((*p >= '0' && *p <= '9') ||
        (*p >= 'a' && *p <= 'z') ||
        (*p >= 'A' && *p <= 'Z')) {
        return 0;
    }

    if (p[0] != '-' || p[1] == '\0' || p[2] != '-' || p[3] != '-') {
        return 0;
    }
    if (p[4] != '\0' && p[4] != '\r') {
        return 0;
    }

    id_out[id_len] = '\0';
    if (id_len_out) {
        *id_len_out = id_len;
    }
    *section_out = p[1];
    return 1;
}

int main(void)
{
    char id[MODSEC_ID_MAX];
    size_t id_len = 0;
    char section = 0;

    assert(parse_modsec_boundary("--fbd13fc1-A--", id, sizeof(id), &id_len, &section));
    assert(section == 'A');
    assert(strcmp(id, "fbd13fc1") == 0);
    assert(id_len == 8);

    assert(parse_modsec_boundary("--fbd13fc1-Z--", id, sizeof(id), &id_len, &section));
    assert(section == 'Z');
    assert(strcmp(id, "fbd13fc1") == 0);

    assert(parse_modsec_boundary("--abc123-H--", id, sizeof(id), &id_len, &section));
    assert(section == 'H');

    /* Empty id rejected */
    assert(!parse_modsec_boundary("--Z--", id, sizeof(id), &id_len, &section));
    assert(!parse_modsec_boundary("---Z--", id, sizeof(id), &id_len, &section));

    /* Truncated / malformed */
    assert(!parse_modsec_boundary("--fbd13fc1-Z-", id, sizeof(id), &id_len, &section));
    assert(!parse_modsec_boundary("-fbd13fc1-Z--", id, sizeof(id), &id_len, &section));
    assert(!parse_modsec_boundary("Message: Access denied", id, sizeof(id), &id_len, &section));

    /* CR-terminated OK */
    assert(parse_modsec_boundary("--fbd13fc1-Z--\r", id, sizeof(id), &id_len, &section));
    assert(section == 'Z');

    /* Overlong id rejected (id_cap-1 max) */
    {
        char longline[MODSEC_ID_MAX + 16];
        memset(longline, 'a', sizeof(longline));
        memcpy(longline, "--", 2);
        /* fill id past MODSEC_ID_MAX-1 */
        memset(longline + 2, 'b', MODSEC_ID_MAX);
        memcpy(longline + 2 + MODSEC_ID_MAX, "-Z--", 5);
        assert(!parse_modsec_boundary(longline, id, MODSEC_ID_MAX, &id_len, &section));
    }

    printf("modsec_audit_boundary_test: ok\n");
    return 0;
}
