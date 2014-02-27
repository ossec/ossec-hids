
#ifndef __LUA_HANDLER_H_INCLUDED__
#define __LUA_HANDLER_H_INCLUDED__

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

typedef struct _lua_handler_t {
    lua_State *L;
    char *name;
    int init;
    int adder;
    int deleter;
    int timer;
    double timer_freq;
} lua_handler_t;


void lua_handler_destroy(lua_handler_t **self);

lua_handler_t *lua_handler_new(const char *name);

int lua_handler_add(lua_handler_t *self, const char *user, const char *ipaddr);

int lua_handler_delete(lua_handler_t *self, const char *user, const char *ipaddr);

#endif
