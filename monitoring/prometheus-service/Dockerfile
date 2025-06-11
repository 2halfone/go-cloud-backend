FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o prometheus-service .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/

COPY --from=builder /app/prometheus-service .
COPY --from=builder /app/config/prometheus.yml ./config/

EXPOSE 9090

CMD ["./prometheus-service"]
