FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy shared module
COPY shared/ ./shared/
COPY ../../shared ../../shared

# Copy prometheus-service files
COPY monitoring/prometheus-service/ ./

# Tidy and download dependencies (go.sum will be generated)
RUN go mod tidy
RUN go mod download
RUN go build -o prometheus-service .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/

COPY --from=builder /app/prometheus-service .
COPY --from=builder /app/config/prometheus.yml ./config/

EXPOSE 9090

CMD ["./prometheus-service"]
