FROM golang:1.20 AS builder
COPY . /build
WORKDIR /build
RUN go build -o crypto-webdav .


FROM alpine:3.17
COPY --from=builder /build/crypto-webdav /crypto-webdav
EXPOSE 8080
CMD ["/crypto-webdav"]
