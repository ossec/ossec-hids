/* Copyright (C) 2026 Atomicorp Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef ANALYSISD_RELOAD_H
#define ANALYSISD_RELOAD_H

extern const char *analysisd_cfgfile;

#define ANALYSISD_RELOAD_OK 0
#define ANALYSISD_RELOAD_FAIL_STAGING (-1)
#define ANALYSISD_RELOAD_FAIL_POST_COMMIT (-2)

void Analysisd_SetCfgfile(const char *cfgfile);
void Analysisd_UnloadAll(void);
int Analysisd_LoadAll(int verbose_load);
int Analysisd_Reload(void);

#endif /* ANALYSISD_RELOAD_H */
