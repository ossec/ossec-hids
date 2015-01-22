

#include "shared.h"


static const struct luaL_Reg ossec_log_functs[] = {
    {NULL, NULL},
};

int luaopen_log(lua_State * L)
{
    luaL_newlib(L, ossec_log_functs);
    return 1; 
}



/*
static const struct luaL_Reg rules_funct[] = {
    {NULL, NULL},
}
*/

