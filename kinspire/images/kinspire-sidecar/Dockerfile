FROM golang:1.22.5 AS builder

WORKDIR /src
ADD go.mod go.sum /src
RUN CGO_ENABLED=0 go build k8s.io/klog/v2 google.golang.org/grpc
ADD . /src
RUN CGO_ENABLED=0 go build -v -o /kinspire-sidecar ./cmd/kinspire-sidecar

FROM gcr.io/distroless/static-debian11:latest
COPY --from=builder /kinspire-sidecar /kinspire-sidecar
