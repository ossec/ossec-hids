FROM ubuntu:18.04

ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update \
    && apt-get --yes install \
        sudo \
        curl \
        wget \
        git \
        build-essential \
        debhelper \
        libssl-dev \
        linux-libc-dev \
        libpcre2-dev \
        pbuilder \
        expect \
        debconf \
        qemu-user-static
COPY ./debian_files /home/ubuntu/debian_files
COPY . /home/ubuntu/ossec-hids
# `docker build` cannot handle `pbuilder create` because it uses `mount` which needs privilege
# RUN /home/ubuntu/ossec-hids/contrib/debian-packages/generate_ossec.sh -d
# RUN /home/ubuntu/ossec-hids/contrib/debian-packages/generate_ossec.sh -u
# RUN /home/ubuntu/ossec-hids/contrib/debian-packages/generate_ossec.sh -b

CMD ["/bin/sh"]
