# Makefile for execd
# Daniel B. Cid <daniel.cid@gmail.com>||<daniel@underlinux.com.br>

PT=../
NAME=ossec-execd

include ../Config.Make

LOCAL = execd.c exec.c config.c
LUA = -I ${PT}external/lua/src ${PT}external/lua/src/liblua.a -lm


OBJS = ${OS_SHARED} ${OS_NET} ${OS_REGEX} ${OS_XML} ${LUA}

addclient:
		${CC} ${CFLAGS} ${OS_LINK} ${LOCAL} ${OBJS} -o ${NAME}
		${CC} ${CFLAGS} -c ${LOCAL}
clean:
		${CLEAN}
build:
		${BUILD}
