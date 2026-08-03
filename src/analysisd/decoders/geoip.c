/* Copyright (C) 2014 Daniel Cid
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


/* GeoIP - Every IP address will have its geolocation added to it */

#ifdef LIBGEOIP_ENABLED


#include "config.h"
#include "os_regex/os_regex.h"
#include "eventinfo.h"
#include "alerts/alerts.h"
#include "decoder.h"


char *GetGeoInfobyIP(char *ip_addr)
{
    int gai_error;
    int mmdb_error;
    int status;
    MMDB_lookup_result_s result;
    MMDB_entry_data_s entry_data;
    char country_code[3];
    char geobuffer[256 + 1];
    char *geodata = NULL;

    if (!geoipdb_ready || !ip_addr) {
        return (NULL);
    }

    result = MMDB_lookup_string(&geoipdb, ip_addr, &gai_error, &mmdb_error);
    if (gai_error != 0 || mmdb_error != MMDB_SUCCESS || !result.found_entry) {
        return (NULL);
    }

    status = MMDB_get_value(&result.entry, &entry_data, "country", "iso_code", NULL);
    if (status != MMDB_SUCCESS || !entry_data.has_data ||
            entry_data.type != MMDB_DATA_TYPE_UTF8_STRING ||
            entry_data.data_size != 2) {
        return (NULL);
    }

    memcpy(country_code, entry_data.utf8_string, 2);
    country_code[2] = '\0';

    /* Prefer English subdivision name when present (City DBs). */
    status = MMDB_get_value(&result.entry, &entry_data,
                            "subdivisions", "0", "names", "en", NULL);
    if (status == MMDB_SUCCESS && entry_data.has_data &&
            entry_data.type == MMDB_DATA_TYPE_UTF8_STRING &&
            entry_data.data_size > 0 && entry_data.data_size < 200) {
        snprintf(geobuffer, sizeof(geobuffer), "%s / %.*s",
                 country_code, (int)entry_data.data_size, entry_data.utf8_string);
        os_strdup(geobuffer, geodata);
        return (geodata);
    }

    /* Fall back to subdivision ISO code. */
    status = MMDB_get_value(&result.entry, &entry_data,
                            "subdivisions", "0", "iso_code", NULL);
    if (status == MMDB_SUCCESS && entry_data.has_data &&
            entry_data.type == MMDB_DATA_TYPE_UTF8_STRING &&
            entry_data.data_size > 0 && entry_data.data_size < 16) {
        snprintf(geobuffer, sizeof(geobuffer), "%s / %.*s",
                 country_code, (int)entry_data.data_size, entry_data.utf8_string);
        os_strdup(geobuffer, geodata);
        return (geodata);
    }

    os_strdup(country_code, geodata);
    return (geodata);
}

#endif
