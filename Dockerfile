# Stage 1: Build
FROM golang:1.25-alpine AS builder
RUN apk add --no-cache git ca-certificates
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -tags netgo -o /build/skink .

# Stage 2: Runtime
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /build/skink /usr/local/bin/skink
EXPOSE 9009-9013 9090 9091 8080
ENTRYPOINT ["/usr/local/bin/skink"]
CMD ["relay"]
