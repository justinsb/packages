FROM golang:latest AS builder

WORKDIR /src
ADD go.mod /src
ADD go.sum /src
ADD cmd/ /src/cmd/
ADD pkg /src/pkg/
RUN ls /src/
RUN CGO_ENABLED=0 go build -o /init-postgres ./cmd/init-postgres

FROM debian:bookworm

# Based on the official postgres Docker image, but simplified

# explicitly set user/group IDs
RUN set -eux; \
	groupadd -r postgres --gid=1000; \
# https://salsa.debian.org/postgresql/postgresql-common/blob/997d842ee744687d99a2b2d95c1083a2615c79e8/debian/postgresql-common.postinst#L32-35
	useradd -r -g postgres --uid=1000 --home-dir=/var/lib/postgresql --shell=/bin/bash postgres; \
# also create the postgres user's home directory with appropriate permissions
# see https://github.com/docker-library/postgres/issues/274
	mkdir -p /var/lib/postgresql; \
	chown -R postgres:postgres /var/lib/postgresql

RUN mkdir -p /var/run/postgresql && chown -R postgres:postgres /var/run/postgresql && chmod 2777 /var/run/postgresql

RUN mkdir -p "/volumes/data/pgdata" && chown -R postgres:postgres "/volumes/data/pgdata" && chmod 770 "/volumes/data/pgdata"

RUN mkdir -p "/secrets" && chown -R postgres:postgres "/secrets" && chmod 770 "/secrets"
RUN mkdir -p "/config" && chown -R postgres:postgres "/config" && chmod 770 "/config"

RUN apt-get update && apt-get install --yes postgresql

RUN apt-get install -y --no-install-recommends locales

ENV LANG en_US.UTF-8  
ENV LC_ALL en_US.UTF-8     

RUN sed -i '/en_US.UTF-8/s/^# //g' /etc/locale.gen && locale-gen

ENV PG_MAJOR 15
ENV PATH $PATH:/usr/lib/postgresql/$PG_MAJOR/bin

COPY --from=builder /init-postgres /init-postgres

ENTRYPOINT [ "/init-postgres" ]
