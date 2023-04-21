FROM golang:1.20 AS builder
ENV GOPROXY=http://goproxy.cn,direct
COPY . /build
WORKDIR /build
RUN go build -o crypto-webdav .


FROM busybox:1.36.0-glibc
COPY --from=builder /build/crypto-webdav /crypto-webdav
EXPOSE 8080
CMD ["/crypto-webdav"]
