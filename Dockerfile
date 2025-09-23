FROM golang:1.24 AS builder
COPY . /build
WORKDIR /build
RUN go build -o crypto-webdav .


FROM ubuntu:22.04
COPY --from=builder /build/crypto-webdav /crypto-webdav
EXPOSE 8080
CMD ["/crypto-webdav"]
