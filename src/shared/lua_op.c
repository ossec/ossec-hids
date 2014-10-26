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

void os_lua_stack_dump(os_lua_t *self)
{
    int i;
    int top = lua_gettop(self->L);

    for (i = 1; i <= top; i++) {
        int t = lua_type(self->L, i);
        switch(t) {
        case LUA_TSTRING:
            d(" %d: %s\n", i, lua_tostring(self->L, i));
            break;
        case LUA_TNUMBER:
            d(" %d: %g\n", i,  lua_tonumber(self->L, i));
            break;
        default:
            d(" %d: %s\n", i, lua_typename(self->L, t));
            break;
        }
    }
}


os_lua_t *lua_states_get(const char *name)
{
    if(lua_states_g) {
        return (os_lua_t *)OSHash_Get(lua_states_g, name); 
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
int lua_states_add(os_lua_t *handler) 
{
    if (lua_states_g == NULL) { 
        lua_states_g = OSHash_Create();
        if (lua_states_g == NULL) {
            return 0;
        }
    }
    return OSHash_Add(lua_states_g, handler->name, handler);
}

os_lua_t *lua_states_del(const char *name) {
    if(lua_states_g == NULL) {
        return NULL; 
    }
    return (os_lua_t *)OSHash_Delete(lua_states_g, name); 
}








os_lua_t *os_lua_getself(lua_State *L)
{
    lua_getfield(L, LUA_REGISTRYINDEX, OS_LUA_REG_NAME);
    os_lua_t *self = lua_touserdata(L, -1);
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


os_lua_t *os_lua_new(const char *name)
{

    os_lua_t *self = (os_lua_t *)malloc(sizeof(os_lua_t));
    if (self == NULL) {
        goto error;
    }

    self->L = luaL_newstate();
    self->name = strdup(name);
    self->sandboxed = 0; 

    //luaL_openlibs(self->L);
    lua_pushlightuserdata(self->L, self);
    lua_setfield(self->L, LUA_REGISTRYINDEX, OS_LUA_REG_NAME);
    /*
    os_lua_load_text(self, 
        "ossec = {}"
        "ossec.version = {}"
        "ossec.version.text = \"%s\""
        "ossec.version.major = %d"
        "ossec.version.minor = %d"
        "ossec.version.patch = %d"
        "ossec.app = {}"
        "ossec.app.name = \"%s\""
    );
    */
    //os_lua_lib_add(self, "ar", ar_functs);
    os_lua_load_ossec(self);

    return self;

error:
    if (self) {
        os_lua_destroy(&self);
    }
    return NULL;
}

/*
int os_lua_lib_add(os_lua_t *self, const char *lib_name, const luaL_Reg *lib_functs)
{
    //luaL_newlib(self->L, lib_functs);
    luaL_newlibtable(self->L,lib_functs);
    luaL_setfuncs(self->L,lib_functs,0);
    lua_setglobal(self->L, lib_name);
    return 0; 
}
*/

int os_lua_load_text(os_lua_t *self, const char *script)
{
    if(luaL_loadstring(self->L, script)) {
        debug2("Error loading script"); 
        goto error; 
    }

    if(lua_pcall(self->L, 0, 0, 0) != 0) {
        debug2("os_lua_load_text error in pcall: %s\n", lua_tostring(self->L, -1));
        goto error;
    }
    return 0;
error:
    return 1;
}


static int ossec_log_debug(lua_State *L)
{
    const char *msg = luaL_checkstring(L, 1);
    debug1("%s\n",msg);
    return(0);
}

static int ossec_log_info(lua_State *L)
{
    const char *msg = luaL_checkstring(L, 1);
    verbose("%s\n", msg);
    return(0);
}

int os_lua_load_ossec(os_lua_t *self)
{
    /* Start ossec table */
    lua_newtable(self->L);

    /* ossec.log() */
    lua_pushstring(self->L, "log");
    lua_pushcfunction(self->L, ossec_log_info);
    lua_settable(self->L, -3);

    /* ossec.debug() */
    lua_pushstring(self->L, "debug");
    lua_pushcfunction(self->L, ossec_log_debug);
    lua_settable(self->L, -3);

    /* Finally set table to name ossec */
    lua_setglobal(self->L, "ossec");


    /* Start user table */
    lua_newtable(self->L); 

    /* Finally set table to name user */
    lua_setglobal(self->L, "user");
    return (0); 
}


int os_lua_load(os_lua_t *self, const char *fname) 
{
    // Loadfile **********************************************
    if(luaL_loadfile(self->L, fname)) {
        debug2("Could not load the file: %s\n", lua_tostring(self->L, -1));
        goto error;
    } 

    if(lua_pcall(self->L, 0, 0, 0) != 0) {
        debug2("os_lua_load error for %s in loadfile pcall: %s\n", fname, lua_tostring(self->L, -1));
        goto error;
    }
    return 0;

error:
    return -1;
}

/*
int os_lua_limit_count(os_lua_t *self, lua_Debug *ar, int count) 
{
    self->ar = ar; 
    self->limit_count = count; 
    return lua_sethook(self->L, &ar, LUA_MASKCOUNT, count);
}
*/


void os_lua_destroy(os_lua_t **self_p)
{
    assert (self_p);
    if (*self_p) {
        os_lua_t *self = *self_p;
        lua_close(self->L);
        free(self->name);
        free (self);
        *self_p = NULL;
    }
}




int os_lua_pcall(os_lua_t *self, int action_func, int nargs, int nresults, int errfunc) {

    
    d(" - os_lua_pcall stack @ start ");
    /* push function stack: 1: table 2: function */
    lua_rawgeti(self->L, LUA_REGISTRYINDEX, action_func);
    /* push table from 1 to stack: 1: table 2: function 3: table */
    lua_pushvalue(self->L, nargs);
    /* remove 1st table from stack: 1: function 2: table */
    lua_remove(self->L, 1);
    d(" ---- os_lua_pcall stack before pcal ");
    os_lua_stack_dump(self);

    if(lua_pcall(self->L, nargs, nresults, errfunc ) != 0 ) {
        debug1("os_lua_pcall error for %s in pcall: %s\n", 
                self->name, 
                lua_tostring(self->L, -1));
        lua_pop(self->L, 1);
        return 0;
    } else {
        return 1;
    }
}

void os_lua_load_lib(os_lua_t *self, const char *libname, lua_CFunction luafunc) 
{
    lua_pushcfunction(self->L, luafunc);
    lua_pushstring(self->L, libname);
    lua_call(self->L, 1, 0);
}

void os_lua_load_core(os_lua_t *self) 
{
    os_lua_load_lib(self,  "", luaopen_base);
    os_lua_load_lib(self, LUA_TABLIBNAME, luaopen_table);
    os_lua_load_lib(self, LUA_STRLIBNAME, luaopen_string);
    os_lua_load_lib(self, LUA_DBLIBNAME, luaopen_debug);

}

int os_lua_load_function(os_lua_t *self, const char *s)
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
int os_lua_tick(os_lua_t *self) 
{

    if (self->timer) {
        lua_rawgeti(self->L, LUA_REGISTRYINDEX, self->timer);
        return os_lua_pcall(self, self->timer, 0, 0, 0);
    }
    return 0;
}

int os_lua_init(os_lua_t *self)
{
    if (self->init) {
        lua_rawgeti(self->L, LUA_REGISTRYINDEX, self->init);
        return os_lua_pcall(self, self->startup, 0, 0, 0);
    } 
    return 0;
}

int os_lua_startup(os_lua_t *self)
{
    if (self->startup) {
        lua_rawgeti(self->L, LUA_REGISTRYINDEX, self->startup);
        return os_lua_pcall(self, self->startup, 0, 0, 0);
    } 
    return 0;
}



int os_lua_shutdown(os_lua_t *self)
{
    if (self->shutdown) {
        lua_rawgeti(self->L, LUA_REGISTRYINDEX, self->shutdown);
        return os_lua_pcall(self, self->shutdown, 0, 0, 0);
    } 
    return 0;
}
*/
