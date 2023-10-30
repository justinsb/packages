FROM golang:1.21.3 AS builder

WORKDIR /src
ADD go.mod go.sum /src
RUN CGO_ENABLED=0 go build k8s.io/klog/v2 google.golang.org/grpc k8s.io/client-go/kubernetes
ADD . /src
RUN CGO_ENABLED=0 go build -v -o /kinspire-server ./cmd/kinspire-server

FROM gcr.io/distroless/static-debian11:latest
COPY --from=builder /kinspire-server /kinspire-server
