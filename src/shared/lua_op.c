#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include "hash_op.h"
#include "debug_op.h"
#include "lua_op.h"



/* Global Lists of States */ 
OSHash *lua_states_g = NULL; 

/*
static void stack_dump(lua_State *L)
{
    int i;
    int top = lua_gettop(L);

    for (i = 1; i <= top; i++) {
        int t = lua_type(L, i);
        switch(t) {
        case LUA_TSTRING:
            printf(" %d: %s\n", i, lua_tostring(L, i));
            break;
        case LUA_TNUMBER:
            printf(" %d: %g\n", i,  lua_tonumber(L, i));
            break;
        default:
            printf(" %d: %s\n", i, lua_typename(L, t));
            break;
        }
    }
}
 */


lua_handler_t *lua_states_get(const char *name)
{
    if(lua_states_g) {
        return (lua_handler_t *)OSHash_Get(lua_states_g, name); 
    } else {
        return NULL; 
    }
}

/* (Just like OSHash) 
 * Returns 0 on error.
 * Returns 1 on duplicated key (not added)
 * Returns 2 on success
 * Key must not be NULL.
 */
int lua_states_add(lua_handler_t *handler) 
{
    if (lua_states_g == NULL) { 
        lua_states_g = OSHash_Create();
        if (lua_states_g == NULL) {
            return 0;
        }
    }
    return OSHash_Add(lua_states_g, handler->name, handler);
}

lua_handler_t *lua_states_del(const char *name) {
    if(lua_states_g == NULL) {
        return NULL; 
    }
    return (lua_handler_t *)OSHash_Delete(lua_states_g, name); 
}








lua_handler_t *lua_handler_getself(lua_State *L)
{
    lua_getfield(L, LUA_REGISTRYINDEX, LUA_HANDLER_REG_NAME);
    lua_handler_t *self = lua_touserdata(L, -1);
    return self;
}


/*
static int ossec_log_debug(lua_State, *L)
{
    
}

static int ossec_log_info(lua_State, *L)
{
    
}

static const struct luaL_Reg ossec_log_functs[] = {
    {"debug",    ossec_log_debug},
    {"info",     ossec_log_info},
    {NULL, NULL},
};

*/


lua_handler_t *lua_handler_new(const char *name)
{

    lua_handler_t *self = (lua_handler_t *)malloc(sizeof(lua_handler_t));
    if (self == NULL) {
        goto error;
    }

    self->L = luaL_newstate();
    self->name = strdup(name);

    luaL_openlibs(self->L);
    lua_pushlightuserdata(self->L, self);
    lua_setfield(self->L, LUA_REGISTRYINDEX, LUA_HANDLER_REG_NAME);
    //lua_handler_lib_add(self, "ar", ar_functs);

    return self;

error:
    //printf("goto: error in new\n");
    if (self) {
        lua_handler_destroy(&self);
    }
    return NULL;
}

int lua_handler_lib_add(lua_handler_t *self, const char *lib_name, const luaL_Reg *lib_functs)
{
    luaL_newlib(self->L, lib_functs);
    lua_setglobal(self->L, lib_name);
    return 0; 
}

int lua_handler_load(lua_handler_t *self, const char *fname) 
{
    // Loadfile **********************************************
    //
    //printf("\n\n");
    if(luaL_loadfile(self->L, fname)) {
        printf("Could not load the file: %s\n", lua_tostring(self->L, -1));
        goto error;
    } 

    if(lua_pcall(self->L, 0, 0, 0) != 0) {
        printf("lua_handler_new error for %s in loadfile pcall: %s\n", fname, lua_tostring(self->L, -1));
        goto error;
    }
    return 0;

error:
    return -1;
}

/*
int lua_handler_limit_count(lua_handler_t *self, lua_Debug *ar, int count) 
{
    self->ar = ar; 
    self->limit_count = count; 
    return lua_sethook(self->L, &ar, LUA_MASKCOUNT, count);
}
*/


void lua_handler_destroy(lua_handler_t **self_p)
{
    assert (self_p);
    if (*self_p) {
        lua_handler_t *self = *self_p;
        lua_close(self->L);
        free(self->name);
        free (self);
        *self_p = NULL;
    }
}




int lua_handler_pcall(lua_handler_t *self, int action_func, int nargs, int nresults, int errfunc) {
    //stack_dump(self->L);
    //lua_rawgeti(self->L, LUA_REGISTRYINDEX, action_func);
    //stack_dump(self->L);
    if(lua_pcall(self->L, nargs, nresults, errfunc ) != 0 ) {
        printf("lau_handler_pcall error for %s in pcall: %s\n", 
                self->name, 
                lua_tostring(self->L, -1));
        //pcall failed exit error
        lua_pop(self->L, 1);
        return 1;
    } else {
        return 0;
    }
}

int lua_handler_load_function(lua_handler_t *self, const char *s)
{
    int result; 
    luaL_loadstring(self->L, s);
    if(lua_pcall(self->L, 0, 1, 0) != 0) {
        debug2("Error in Lua: \n %s\n", s); 
        debug2("Error: %s\n", lua_tostring(self->L, -1));
        lua_pop(self->L, 1);
        goto error; 
    } else if (lua_isfunction(self->L, -1)) {
        result = luaL_ref(self->L, LUA_REGISTRYINDEX);
        if (result == LUA_REFNIL) {
            debug2("Error could not luaL_reg function: %s\n", s );
            goto error; 
        }
        return(result); /* return int that will allow ref to function in future */
    }
error: 
    return(0);
}
/*
int lua_handler_tick(lua_handler_t *self) 
{

    if (self->timer) {
        lua_rawgeti(self->L, LUA_REGISTRYINDEX, self->timer);
        return lua_handler_pcall(self, self->timer, 0, 0, 0);
    }
    return 0;
}

int lua_handler_init(lua_handler_t *self)
{
    if (self->init) {
        lua_rawgeti(self->L, LUA_REGISTRYINDEX, self->init);
        return lua_handler_pcall(self, self->startup, 0, 0, 0);
    } 
    return 0;
}

int lua_handler_startup(lua_handler_t *self)
{
    if (self->startup) {
        lua_rawgeti(self->L, LUA_REGISTRYINDEX, self->startup);
        return lua_handler_pcall(self, self->startup, 0, 0, 0);
    } 
    return 0;
}



int lua_handler_shutdown(lua_handler_t *self)
{
    if (self->shutdown) {
        lua_rawgeti(self->L, LUA_REGISTRYINDEX, self->shutdown);
        return lua_handler_pcall(self, self->shutdown, 0, 0, 0);
    } 
    return 0;
}
*/
