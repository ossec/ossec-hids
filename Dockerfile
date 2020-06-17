FROM ubuntu:16.04

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
# RUN cd /home/ubuntu/ossec-hids/contrib/debian-packages \
#     && ./generate_ossec_xenial_arm64.sh -d
# RUN DIST=xenial ARCH=arm64 pbuilder create --configfile /home/ubuntu/ossec-hids/contrib/debian-packages/pbuilderrc
# RUN cd /home/ubuntu/ossec-hids/contrib/debian-packages \
#     && ./generate_ossec_xenial_arm64.sh -u
# RUN cd /home/ubuntu/ossec-hids/contrib/debian-packages \
#     && ./generate_ossec_xenial_arm64.sh -b

CMD ["/bin/sh"]
