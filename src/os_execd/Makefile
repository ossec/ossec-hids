# Makefile for execd
# Daniel B. Cid <daniel.cid@gmail.com>||<daniel@underlinux.com.br>

PT=../
NAME=ossec-execd

include ../Config.Make

LOCAL = execd.c exec.c config.c
LUA = -I${PT}external/lua/src -L${PT}external/lua/src  -llua -lm


OBJS = ${OS_SHARED} ${OS_NET} ${OS_REGEX} ${OS_XML} ${LUA}

		


addclient:
		${CC} ${CFLAGS} ${OS_LINK} ${LOCAL} ${OBJS} -o ${NAME}
		${CC} ${CFLAGS} -c ${LOCAL}

lua_tester: 
		#${CC} ${CFLAGS} ${OS_LINK} ${LUA} lua_handler.c -o lua_tester -v 
		${CC}  lua_handler.c -o lua_tester ${LUA}

clean:
		${CLEAN} lua_tester

build:
		${BUILD}
