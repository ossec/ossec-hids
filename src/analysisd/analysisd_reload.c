/* Copyright (C) 2026 Atomicorp Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef ARGV0
#define ARGV0 "ossec-analysisd"
#endif

#include "shared.h"
#include "analysisd.h"
#include "analysisd_reload.h"
#include "active-response.h"
#include "config.h"
#include "rules.h"
#include "lists.h"
#include "decoders/decoder.h"
#include "fts.h"
#include "accumulator.h"

#ifdef LIBGEOIP_ENABLED
#include "GeoIP.h"
extern GeoIP *geoipdb;
#endif

extern int ar_flag;

const char *analysisd_cfgfile = NULL;
static int analysisd_reload_count = 0;

#ifdef LIBGEOIP_ENABLED
static GeoIP *analysisd_staging_geoip = NULL;
#endif

void Analysisd_SetCfgfile(const char *cfgfile)
{
    analysisd_cfgfile = cfgfile;
}

void Analysisd_UnloadAll(void)
{
    OS_AbandonRuleList();

    if (Config.g_rules_hash) {
        OSHash_Free(Config.g_rules_hash);
        Config.g_rules_hash = NULL;
    }

    OS_FreeLists();
    OS_AbandonOSDecoderList();
    OS_DestroyDecoderStore();

    FreeARConfig();
    AR_Init();

    FTS_Free();
    Accumulate_Free();

#ifdef LIBGEOIP_ENABLED
    if (geoipdb) {
        GeoIP_delete(geoipdb);
        geoipdb = NULL;
    }
#endif

    FreeConfig(&Config);
    memset(&Config, 0, sizeof(Config));
}

static int analysisd_load_decoders(_Config *cfg, int verbose_load)
{
    int c;
    size_t saved_order;

    OS_CreateOSDecoderList();

    saved_order = Config.decoder_order_size;
    Config.decoder_order_size = cfg->decoder_order_size;

    if (!cfg->decoders) {
        if (!ReadDecodeXML(XML_DECODER)) {
            Config.decoder_order_size = saved_order;
            return (OS_INVALID);
        }

        c = ReadDecodeXML(XML_LDECODER);
        if (!c) {
            if (c != -2) {
                Config.decoder_order_size = saved_order;
                return (OS_INVALID);
            }
        } else if (verbose_load) {
            verbose("%s: INFO: Reading local decoder file.", ARGV0);
        }
    } else {
        char **decodersfiles = cfg->decoders;

        while (decodersfiles && *decodersfiles) {
            if (verbose_load) {
                verbose("%s: INFO: Reading decoder file %s.", ARGV0, *decodersfiles);
            }
            if (!ReadDecodeXML(*decodersfiles)) {
                Config.decoder_order_size = saved_order;
                return (OS_INVALID);
            }

            free(*decodersfiles);
            decodersfiles++;
        }
    }

    Config.decoder_order_size = saved_order;
    SetDecodeXML();
    return (0);
}

static int analysisd_load_lists(_Config *cfg, int verbose_load)
{
    char **listfiles;

    Lists_OP_CreateLists();
    listfiles = cfg->lists;
    while (listfiles && *listfiles) {
        if (verbose_load) {
            verbose("%s: INFO: Reading loading the lists file: '%s'", ARGV0, *listfiles);
        }
        if (Lists_OP_LoadList(*listfiles) < 0) {
            return (OS_INVALID);
        }
        free(*listfiles);
        listfiles++;
    }

    if (cfg->lists) {
        free(cfg->lists);
        cfg->lists = NULL;
    }

    return (0);
}

static int analysisd_load_rules(_Config *cfg, int verbose_load)
{
    char **rulesfiles;

    Rules_OP_CreateRules();

    rulesfiles = cfg->includes;
    while (rulesfiles && *rulesfiles) {
        if (verbose_load) {
            verbose("%s: INFO: Reading rules file: '%s'", ARGV0, *rulesfiles);
        }
        if (Rules_OP_ReadRules(*rulesfiles) < 0) {
            return (OS_INVALID);
        }

        free(*rulesfiles);
        rulesfiles++;
    }

    if (cfg->includes) {
        free(cfg->includes);
        cfg->includes = NULL;
    }

    OS_ListLoadRules();
    return (0);
}

static int analysisd_finish_rules(_Config *cfg, int verbose_load)
{
    int total_rules;
    RuleNode *tmp_node;

    tmp_node = OS_GetFirstRule();
    total_rules = _setlevels(tmp_node, 0);
    if (verbose_load) {
        verbose("%s: INFO: Total rules enabled: '%d'", ARGV0, total_rules);
    }

    cfg->g_rules_hash = OSHash_Create();
    if (!cfg->g_rules_hash) {
        return (OS_INVALID);
    }

    AddHash_Rule(cfg->g_rules_hash, tmp_node);
    return (0);
}

static const char *analysisd_cfgfile_for_read(void)
{
    const char *cfgfile = analysisd_cfgfile;

    if (!cfgfile) {
        return (NULL);
    }

    if (isChroot()) {
        return (OSSECCONF);
    }

    return (cfgfile);
}

static void analysisd_staging_abort(_Config *staging_cfg)
{
    OS_RuleListStagingAbort();
    OS_DecoderListStagingAbort();
    OS_ListsStagingAbort();
    OS_DecoderStoreStagingAbort();

#ifdef LIBGEOIP_ENABLED
    if (analysisd_staging_geoip) {
        GeoIP_delete(analysisd_staging_geoip);
        analysisd_staging_geoip = NULL;
    }
#endif

    if (staging_cfg->g_rules_hash) {
        OSHash_Free(staging_cfg->g_rules_hash);
        staging_cfg->g_rules_hash = NULL;
    }

    FreeConfig(staging_cfg);
    memset(staging_cfg, 0, sizeof(_Config));
}

static int Analysisd_LoadAllStaging(_Config *staging_cfg, int verbose_load)
{
    const char *cfgfile = analysisd_cfgfile_for_read();

    if (!cfgfile || !staging_cfg) {
        return (OS_INVALID);
    }

    OS_RuleListStagingBegin();
    OS_DecoderListStagingBegin();
    OS_ListsStagingBegin();
    OS_DecoderStoreStagingBegin();

    memset(staging_cfg, 0, sizeof(_Config));

    staging_cfg->decoder_order_size = (size_t)getDefine_IntDefault("analysisd", "decoder_order_size", 8, 8, MAX_DECODER_ORDER_SIZE);

    if (GlobalConfInto(staging_cfg, cfgfile) < 0) {
        analysisd_staging_abort(staging_cfg);
        return (OS_INVALID);
    }

#ifdef LIBGEOIP_ENABLED
    if (staging_cfg->geoipdb_file) {
        analysisd_staging_geoip = GeoIP_open(staging_cfg->geoipdb_file, GEOIP_INDEX_CACHE);
        if (analysisd_staging_geoip == NULL) {
            merror("%s: ERROR: Unable to open GeoIP database from: %s (disabling GeoIP).", ARGV0, staging_cfg->geoipdb_file);
        }
    }
#endif

    if (analysisd_load_decoders(staging_cfg, verbose_load) < 0) {
        analysisd_staging_abort(staging_cfg);
        return (OS_INVALID);
    }

    if (analysisd_load_lists(staging_cfg, verbose_load) < 0) {
        analysisd_staging_abort(staging_cfg);
        return (OS_INVALID);
    }

    if (analysisd_load_rules(staging_cfg, verbose_load) < 0) {
        analysisd_staging_abort(staging_cfg);
        return (OS_INVALID);
    }

    if (analysisd_finish_rules(staging_cfg, verbose_load) < 0) {
        analysisd_staging_abort(staging_cfg);
        return (OS_INVALID);
    }

    staging_cfg->logfw = (u_int8_t) getDefine_IntDefault("analysisd", "log_fw", 0, 0, 1);

    return (0);
}

static void analysisd_commit_config(_Config *staging_cfg)
{
    if (Config.g_rules_hash) {
        OSHash_Free(Config.g_rules_hash);
        Config.g_rules_hash = NULL;
    }

    FreeConfig(&Config);
    memcpy(&Config, staging_cfg, sizeof(_Config));
    memset(staging_cfg, 0, sizeof(_Config));
}

int Analysisd_LoadAll(int verbose_load)
{
    const char *cfgfile = analysisd_cfgfile_for_read();

    if (!cfgfile) {
        return (OS_INVALID);
    }

    Config.decoder_order_size = (size_t)getDefine_IntDefault("analysisd", "decoder_order_size", 8, 8, MAX_DECODER_ORDER_SIZE);

    if (AR_ReadConfig(cfgfile) < 0) {
        return (OS_INVALID);
    }

    if (GlobalConf(cfgfile) < 0) {
        return (OS_INVALID);
    }

    Config.ar = ar_flag;
    if (Config.ar == -1) {
        Config.ar = 0;
    }

#ifdef LIBGEOIP_ENABLED
    if (Config.geoipdb_file) {
        geoipdb = GeoIP_open(Config.geoipdb_file, GEOIP_INDEX_CACHE);
        if (geoipdb == NULL) {
            merror("%s: ERROR: Unable to open GeoIP database from: %s (disabling GeoIP).", ARGV0, Config.geoipdb_file);
        }
    }
#endif

    if (analysisd_load_decoders(&Config, verbose_load) < 0) {
        return (OS_INVALID);
    }

    if (analysisd_load_lists(&Config, verbose_load) < 0) {
        return (OS_INVALID);
    }

    if (analysisd_load_rules(&Config, verbose_load) < 0) {
        return (OS_INVALID);
    }

    if (analysisd_finish_rules(&Config, verbose_load) < 0) {
        return (OS_INVALID);
    }

    Config.logfw = (u_int8_t) getDefine_IntDefault("analysisd", "log_fw", 0, 0, 1);

    return (0);
}

static int analysisd_get_max_config_reloads(void)
{
    return getDefine_IntDefault("analysisd", "max_config_reloads", 10, 0, 1000);
}

int Analysisd_Reload(void)
{
    _Config staging_cfg;
    const char *cfgfile;
    int max_reloads;
    int rc = ANALYSISD_RELOAD_OK;

    cfgfile = analysisd_cfgfile_for_read();
    if (!cfgfile) {
        merror("%s: ERROR: No configuration file path for reload.", ARGV0);
        return (ANALYSISD_RELOAD_FAIL_STAGING);
    }

    max_reloads = analysisd_get_max_config_reloads();
    if (max_reloads > 0 && analysisd_reload_count >= max_reloads) {
        merror("%s: WARNING: Maximum configuration reload count (%d) reached. "
               "Restart ossec-analysisd to reload again.", ARGV0, max_reloads);
        return (ANALYSISD_RELOAD_FAIL_STAGING);
    }

    if (Analysisd_LoadAllStaging(&staging_cfg, 1) < 0) {
        merror("%s: ERROR: Error reloading configuration (using previous configuration).", ARGV0);
        return (ANALYSISD_RELOAD_FAIL_STAGING);
    }

    if (AR_LoadConfigStaging(cfgfile) < 0) {
        analysisd_staging_abort(&staging_cfg);
        merror("%s: ERROR: Active response configuration invalid (using previous configuration).", ARGV0);
        return (ANALYSISD_RELOAD_FAIL_STAGING);
    }

    staging_cfg.ar = ar_flag;
    if (staging_cfg.ar == -1) {
        staging_cfg.ar = 0;
    }

    OS_RuleListStagingCommit();
    OS_DecoderListStagingCommit();
    OS_ListsStagingCommit();
    OS_DecoderStoreStagingCommit();

    analysisd_commit_config(&staging_cfg);

    if (AR_CommitConfig() < 0) {
        AR_AbortConfigStaging();
        Config.ar = (ar_flag == -1) ? 0 : (u_int8_t) ar_flag;
        merror("%s: ERROR: Active response configuration could not be committed after reload.", ARGV0);
        rc = ANALYSISD_RELOAD_FAIL_POST_COMMIT;
    }

#ifdef LIBGEOIP_ENABLED
    if (rc == ANALYSISD_RELOAD_OK && analysisd_staging_geoip) {
        GeoIP *old_geoip = geoipdb;

        geoipdb = analysisd_staging_geoip;
        analysisd_staging_geoip = NULL;
        if (old_geoip) {
            GeoIP_delete(old_geoip);
        }
    } else if (analysisd_staging_geoip) {
        GeoIP_delete(analysisd_staging_geoip);
        analysisd_staging_geoip = NULL;
    }
#endif

    FTS_Free();
    if (!FTS_Init()) {
        merror("%s: ERROR: FTS module could not be re-initialized after reload.", ARGV0);
        rc = ANALYSISD_RELOAD_FAIL_POST_COMMIT;
    }

    Accumulate_Free();
    if (!Accumulate_Init()) {
        merror("%s: ERROR: Accumulator could not be re-initialized after reload.", ARGV0);
        rc = ANALYSISD_RELOAD_FAIL_POST_COMMIT;
    }

    SyscheckRefreshDecoderIds();
    RootcheckRefreshDecoderIds();
    HostinfoRefreshDecoderIds();

    if (rc == ANALYSISD_RELOAD_OK) {
        analysisd_reload_count++;
        merror("%s: INFO: Configuration reloaded successfully.", ARGV0);
    } else {
        merror("%s: ERROR: Partial reload applied (rules/decoders updated); "
               "restart ossec-analysisd recommended.", ARGV0);
    }

    return (rc);
}
