### SET UP APP ENVIRONMENT ###
FROM ubuntu:24.04 AS app

# install WolfSSL
RUN apt update
RUN apt install -y git autoconf automake libtool make gcc

RUN cd /tmp && git clone --branch v5.8.2-stable --depth 1 --single-branch https://github.com/wolfSSL/wolfssl
WORKDIR /tmp/wolfssl/

RUN ./autogen.sh
RUN ./configure
RUN make install
RUN ldconfig


### SET UP JAIL ENVIRONMENT ###
FROM pwn.red/jail
COPY --from=app / /srv

# copy challenge file over
COPY challenge /srv/app/run
COPY flag.txt /srv/app/flag.txt

# setup jail
ENV JAIL_TIME=60 JAIL_MEM=50M JAIL_CONNS_PER_IP=10 JAIL_CPU=500