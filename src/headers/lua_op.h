#ifndef __LUA_OP_H
#define __LUA_OP_H

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>


#define LUA_HANDLER_REG_NAME "__lua_handler"
#define LUA_HANDLE_DEFAULT_FAILURE_MAX 5
#define LUA_STATE_DEFAULT "default"

typedef struct _lua_handler_t {
    lua_State *L;
    char *name;
    lua_Debug *ar;
    double timer_freq;
} lua_handler_t;



lua_handler_t *lua_states_get(const char *name);
int lua_states_add(lua_handler_t *handler);
lua_handler_t *lua_states_del(const char *name);

lua_handler_t *lua_handler_new(const char *name);
int lua_handler_lib_add(lua_handler_t *self, const char *lib_name, const luaL_Reg *lib_functs);
int lua_handler_load(lua_handler_t *self, const char *fname);
void lua_handler_destroy(lua_handler_t **self_p);
int lua_handler_pcall(lua_handler_t *self, int action_func, int nargs, int nresults, int errfunc);
int lua_handler_load_function(lua_handler_t *self, const char *s);

#endif 

