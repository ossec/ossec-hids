/* Copyright (C) 2014 Daniel Cid
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


/* GeoIP - MaxMind MMDB enrichment for event IPs */

#ifdef LIBGEOIP_ENABLED


#include "config.h"
#include "os_regex/os_regex.h"
#include "eventinfo.h"
#include "alerts/alerts.h"
#include "decoder.h"

#include <string.h>

/* Copy a UTF-8 MMDB string into a NUL-terminated heap buffer. */
static char *mmdb_strdup_utf8(const MMDB_entry_data_s *entry_data)
{
    char *out;

    if (!entry_data->has_data || entry_data->type != MMDB_DATA_TYPE_UTF8_STRING ||
            entry_data->data_size == 0) {
        return (NULL);
    }

    os_calloc(entry_data->data_size + 1, sizeof(char), out);
    memcpy(out, entry_data->utf8_string, entry_data->data_size);
    out[entry_data->data_size] = '\0';
    return (out);
}

static void lookup_city(const char *ip_addr,
                        char **country, char **region, char **city, char **display)
{
    int gai_error;
    int mmdb_error;
    int status;
    MMDB_lookup_result_s result;
    MMDB_entry_data_s entry_data;
    char geobuffer[256 + 1];

    *country = NULL;
    *region = NULL;
    *city = NULL;
    *display = NULL;

    if (!geoipdb_ready || !ip_addr) {
        return;
    }

    result = MMDB_lookup_string(&geoipdb, ip_addr, &gai_error, &mmdb_error);
    if (gai_error != 0 || mmdb_error != MMDB_SUCCESS || !result.found_entry) {
        return;
    }

    status = MMDB_get_value(&result.entry, &entry_data, "country", "iso_code", NULL);
    if (status != MMDB_SUCCESS || !entry_data.has_data ||
            entry_data.type != MMDB_DATA_TYPE_UTF8_STRING ||
            entry_data.data_size != 2) {
        return;
    }
    *country = mmdb_strdup_utf8(&entry_data);
    if (!*country) {
        return;
    }

    status = MMDB_get_value(&result.entry, &entry_data,
                            "subdivisions", "0", "names", "en", NULL);
    if (status == MMDB_SUCCESS) {
        *region = mmdb_strdup_utf8(&entry_data);
    }
    if (!*region) {
        status = MMDB_get_value(&result.entry, &entry_data,
                                "subdivisions", "0", "iso_code", NULL);
        if (status == MMDB_SUCCESS) {
            *region = mmdb_strdup_utf8(&entry_data);
        }
    }

    status = MMDB_get_value(&result.entry, &entry_data, "city", "names", "en", NULL);
    if (status == MMDB_SUCCESS) {
        *city = mmdb_strdup_utf8(&entry_data);
    }

    if (*region) {
        snprintf(geobuffer, sizeof(geobuffer), "%s / %s", *country, *region);
    } else {
        snprintf(geobuffer, sizeof(geobuffer), "%s", *country);
    }
    os_strdup(geobuffer, *display);
}

static void lookup_asn(const char *ip_addr, char **asn, char **as_org)
{
    int gai_error;
    int mmdb_error;
    int status;
    MMDB_lookup_result_s result;
    MMDB_entry_data_s entry_data;
    char asnbuf[16];

    *asn = NULL;
    *as_org = NULL;

    if (!geoipasn_ready || !ip_addr) {
        return;
    }

    result = MMDB_lookup_string(&geoipasn, ip_addr, &gai_error, &mmdb_error);
    if (gai_error != 0 || mmdb_error != MMDB_SUCCESS || !result.found_entry) {
        return;
    }

    status = MMDB_get_value(&result.entry, &entry_data, "autonomous_system_number", NULL);
    if (status == MMDB_SUCCESS && entry_data.has_data &&
            entry_data.type == MMDB_DATA_TYPE_UINT32) {
        snprintf(asnbuf, sizeof(asnbuf), "%u", entry_data.uint32);
        os_strdup(asnbuf, *asn);
    }

    status = MMDB_get_value(&result.entry, &entry_data, "autonomous_system_organization", NULL);
    if (status == MMDB_SUCCESS) {
        *as_org = mmdb_strdup_utf8(&entry_data);
    }
}

void OS_GeoIP_Enrich(Eventinfo *lf, int is_src)
{
    const char *ip;
    char *country = NULL;
    char *region = NULL;
    char *city = NULL;
    char *display = NULL;
    char *asn = NULL;
    char *as_org = NULL;

    if (!lf) {
        return;
    }

    ip = is_src ? lf->srcip : lf->dstip;
    if (!ip) {
        return;
    }

    lookup_city(ip, &country, &region, &city, &display);
    lookup_asn(ip, &asn, &as_org);

    if (is_src) {
        if (!lf->src_country && country) {
            lf->src_country = country;
            country = NULL;
        }
        if (!lf->src_region && region) {
            lf->src_region = region;
            region = NULL;
        }
        if (!lf->src_city && city) {
            lf->src_city = city;
            city = NULL;
        }
        if (!lf->srcgeoip && display) {
            lf->srcgeoip = display;
            display = NULL;
        }
        if (!lf->srcasn && asn) {
            lf->srcasn = asn;
            asn = NULL;
        }
        if (!lf->srcas_org && as_org) {
            lf->srcas_org = as_org;
            as_org = NULL;
        }
    } else {
        if (!lf->dst_country && country) {
            lf->dst_country = country;
            country = NULL;
        }
        if (!lf->dst_region && region) {
            lf->dst_region = region;
            region = NULL;
        }
        if (!lf->dst_city && city) {
            lf->dst_city = city;
            city = NULL;
        }
        if (!lf->dstgeoip && display) {
            lf->dstgeoip = display;
            display = NULL;
        }
        if (!lf->dstasn && asn) {
            lf->dstasn = asn;
            asn = NULL;
        }
        if (!lf->dstas_org && as_org) {
            lf->dstas_org = as_org;
            as_org = NULL;
        }
    }

    free(country);
    free(region);
    free(city);
    free(display);
    free(asn);
    free(as_org);
}

char *GetGeoInfobyIP(char *ip_addr)
{
    char *country = NULL;
    char *region = NULL;
    char *city = NULL;
    char *display = NULL;

    lookup_city(ip_addr, &country, &region, &city, &display);
    free(country);
    free(region);
    free(city);
    return (display);
}

#endif
