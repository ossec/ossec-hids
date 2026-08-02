/* Copyright (C) 2015 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "jsonout.h"
#include "alerts/getloglocation.h"
#include "format/to_json.h"

void jsonout_output_event(const Eventinfo *lf)
{
    char *json_alert = Eventinfo_to_jsonstr(lf);

    analysisd_log_io_lock();
    fprintf(_jflog,
            "%s\n",
            json_alert);

    fflush(_jflog);
    analysisd_log_io_unlock();
    free(json_alert);
    return;
}
void jsonout_output_archive(const Eventinfo *lf)
{
    char *json_alert = Archiveinfo_to_jsonstr(lf);

    analysisd_log_io_lock();
    fprintf(_ejflog,
            "%s\n",
            json_alert);

    fflush(_ejflog);
    analysisd_log_io_unlock();
    free(json_alert);
    return;
}
