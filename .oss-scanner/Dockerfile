# Anthropic OSS Scanner build environment for OSSEC HIDS.
# https://red.anthropic.com/oss-scanner/
#
# Network is available during this image build only. The audit that follows
# runs offline, so every dependency and binary the agent may need must be
# present when this Dockerfile finishes.
FROM debian:bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    CC=gcc \
    CXX=g++

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates \
      build-essential \
      clang \
      pkg-config \
      git \
      python3 \
      zlib1g-dev \
      libssl-dev \
      libpcre2-dev \
      libsystemd-dev \
      libsqlite3-dev \
      libmagic-dev \
      check \
      libsubunit-dev \
      expect \
      procps \
      gdb \
    && rm -rf /var/lib/apt/lists/*

# Scanner contract: the repository checkout is the Docker build context.
COPY . /src
WORKDIR /src

# Do not pass CFLAGS= on the make command line: that replaces the Makefile's
# CFLAGS and drops -I./external/compat (imsg.h). DEBUG=1 adds -g.
RUN make -C src clean \
    && make -C src -j"$(nproc)" \
         TARGET=server \
         DEBUG=1 \
         ZLIB_SYSTEM=yes \
         PCRE2_SYSTEM=yes

# Preserve server binaries, then build the Unix agent for agent-side paths.
RUN mkdir -p /src/.oss-scanner/bin/server \
    && find src -maxdepth 1 -type f -executable -exec cp -a {} /src/.oss-scanner/bin/server/ \; \
    && make -C src clean \
    && make -C src -j"$(nproc)" \
         TARGET=agent \
         DEBUG=1 \
         ZLIB_SYSTEM=yes \
         PCRE2_SYSTEM=yes \
    && mkdir -p /src/.oss-scanner/bin/agent \
    && find src -maxdepth 1 -type f -executable -exec cp -a {} /src/.oss-scanner/bin/agent/ \;

# Leave /src/src as a fresh DEBUG server tree (highest-priority surface).
RUN make -C src clean \
    && make -C src -j"$(nproc)" \
         TARGET=server \
         DEBUG=1 \
         ZLIB_SYSTEM=yes \
         PCRE2_SYSTEM=yes

# Optional unit tests (Check framework). Never fail the image build.
RUN (make -C src TARGET=server DEBUG=1 ZLIB_SYSTEM=yes PCRE2_SYSTEM=yes \
         LDFLAGS="-lcheck -lsubunit -lm -lrt -lpthread" \
         test_os_zlib test_os_xml test_os_regex test_os_crypto test_shared \
     && ./src/test_os_zlib && ./src/test_os_xml && ./src/test_os_regex \
     && ./src/test_os_crypto && ./src/test_shared) \
    || echo "WARNING: unit tests reported failures"
