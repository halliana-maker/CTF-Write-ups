FROM pwn.red/jail

COPY --from=ubuntu@sha256:c35e29c9450151419d9448b0fd75374fec4fff364a27f176fb458d472dfc9e54 / /srv
RUN mkdir -p /srv/app
WORKDIR /srv/app
COPY --chmod=555 chall.sh run
COPY flag.txt /srv/flag.txt

# only keep some necessary binaries for the challenge :D
RUN mv /bin/cat /bin/cut /bin/md5sum /bin/find /bin/grep /bin/head /bin/ls /bin/strings /bin/uniq /bin/tail /tmp/ && \
    rm /bin/* && \
    /tmp/find /tmp -type f -executable ! -name "nsjail.cfg" -exec mv {} /bin/ \;

ENV JAIL_PIDS=10 JAIL_MEM=5M JAIL_TIME=20 JAIL_POW=0