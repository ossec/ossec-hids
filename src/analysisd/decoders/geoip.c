/* @(#) $Id: ./src/analysisd/decoders/geoip.c, 2014/03/08 dcid Exp $
 */

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
#include <maxminddb.h>


char *GetGeoInfobyIP(char *ip_addr)
{

    //debug1("%s: DEBUG: Entered GetGeoInfobyIP", __local_name);

    if(!ip_addr)
    {
        debug1("%s: DEBUG: (geo) ip_addr is NULL");
        return(NULL);
    }
    if(!Config.geoipdb_file) {
        debug1("%s: DEBUG: (geo) Config.geoipdb_file (geoipdb) is null");
        return(NULL);
    }

    int gai_error, mmdb_error;
    MMDB_lookup_result_s geo_result = MMDB_lookup_string(&geoipdb, ip_addr, &gai_error, &mmdb_error);
    if(gai_error != 0) {
        merror("%s: ERROR: error from (geo) getaddrinfo for %s: %s", __local_name, ip_addr, gai_strerror(gai_error));
        return(NULL);
    }

    if(mmdb_error != MMDB_SUCCESS) {
        merror("%s: ERROR: Error from geoip: %s", __local_name, MMDB_strerror(mmdb_error));
        return(NULL);
    }

    MMDB_entry_data_list_s *entry_data_list = NULL;

    if(geo_result.found_entry) {
        int entry_status = MMDB_get_entry_data_list(&geo_result.entry, &entry_data_list);
        if(entry_status != MMDB_SUCCESS) {
            merror("%s: ERROR: Error during geoip lookup: %s", __local_name, MMDB_strerror(entry_status));
            return(NULL);
        }

        if(entry_data_list != NULL) {
            /* XXX what do? */
            /* I need country code, region */
            static char country_code[3];
            MMDB_entry_data_s entry_data;
            int cc = MMDB_get_value(&geo_result.entry, &entry_data, "country", "iso_code", NULL);
            if(cc != MMDB_SUCCESS) {
                MMDB_free_entry_data_list(entry_data_list);
                return(NULL);
            }
            if(!entry_data.has_data || entry_data.type != MMDB_DATA_TYPE_UTF8_STRING) {
                MMDB_free_entry_data_list(entry_data_list);
                return(NULL);
            }
            snprintf(country_code, 3, "%.2s", entry_data.utf8_string);
            if(strnlen(country_code, 3) != 2) {
                debug1("%s: DEBUG: (geo) country_code is wrong?", __local_name);
            }

            MMDB_free_entry_data_list(entry_data_list);
            return(country_code);
        }
    } else {
        debug1("%s: DEBUG: No entry for %s", __local_name, ip_addr);
        MMDB_free_entry_data_list(entry_data_list);
        return(NULL);
    }

    /* Should not get here */
    return(NULL);
}

#endif

