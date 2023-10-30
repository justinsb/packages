FROM golang:latest AS builder

WORKDIR /src
ADD go.mod /src
ADD go.sum /src
ADD cmd/ /src/cmd/
ADD pkg /src/pkg/
RUN ls /src/
RUN CGO_ENABLED=0 go build -o /init-gitea ./cmd/init-gitea

FROM gitea/gitea:1.20.5

RUN mkdir -p "/sockets" && chown -R 1000:1000 "/sockets" && chmod 770 "/sockets"
RUN mkdir -p "/config" && chown -R 1000:1000 "/config" && chmod 770 "/config"

COPY --from=builder /init-gitea /init-gitea

ENTRYPOINT [ "/init-gitea" ]



