#ifndef __LUA_OP_H
#define __LUA_OP_H

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>


#define OS_LUA_REG_NAME "__os_lua"
#define OS_LUA_DEFAULT_FAILURE_MAX 5
#define LUA_STATE_DEFAULT "default"

typedef struct _os_lua_t {
    lua_State *L;
    char *name;
    lua_Debug *ar;
    int sandboxed; 
} os_lua_t;



os_lua_t *lua_states_get(const char *name);
int lua_states_add(os_lua_t *handler);
os_lua_t *lua_states_del(const char *name);

os_lua_t *os_lua_new(const char *name);
void os_lua_stack_dump(os_lua_t *self);
/*int os_lua_lib_add(os_lua_t *self, const char *lib_name, const luaL_Reg *lib_functs);*/
int os_lua_load(os_lua_t *self, const char *fname);
int os_lua_load_ossec(os_lua_t *self);
void os_lua_destroy(os_lua_t **self_p);
int os_lua_pcall(os_lua_t *self, int action_func, int nargs, int nresults, int errfunc);
void os_lua_load_lib(os_lua_t *self, const char *libname, lua_CFunction luafunc);
void os_lua_load_core(os_lua_t *self);
int os_lua_load_function(os_lua_t *self, const char *s);

#endif 

