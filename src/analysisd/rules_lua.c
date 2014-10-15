

#include "shared.h"


static int ossec_log_debug(lua_State *L)
{
    const char *msg = luaL_checkstring(L, 1);
    printf("-> new debug\n");
    debug1("%s\n",msg);
    return(0);
}

static int ossec_log_info(lua_State *L)
{
    const char *msg = luaL_checkstring(L, 1);
    verbose("%s\n", msg);
    return(0);
}

static const struct luaL_Reg ossec_log_functs[] = {
    {"debug",    ossec_log_debug},
    {"info",     ossec_log_info},
    {NULL, NULL},
};

int luaopen_log(lua_State * L)
{
    luaL_newlib(L, ossec_log_functs);
    printf("setting log\n\n\n\n");
    return 0; 
}



/*
static const struct luaL_Reg rules_funct[] = {
    {NULL, NULL},
}
*/

