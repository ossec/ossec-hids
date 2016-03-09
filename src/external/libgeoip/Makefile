# Makefile for zlib.
# Daniel B. Cid <dcid@ossec.net>
# http://www.ossec.net

NAME=zlib
PT=../../

include ${PT}Config.Make

shared:
		${CC} -DPACKAGE_VERSION=\"OSSEC201601\" -DGEOIPDATADIR=\"/\" -c ${CFLAGS} ${SOURCES}
		ar cru libgeoip.a ${OBJECTS}
		ranlib libgeoip.a
clean:
		${CLEAN} ../../headers/GeoIP.h ../../headers/GeoIPCity.h ../libgeoip.a

ossec:
		cp -pr GeoIP.h GeoIPCity.h ../../headers/
		cp -pr libgeoip.a ../
