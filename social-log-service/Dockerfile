# syntax=docker/dockerfile:1
FROM golang:1.24.3-alpine
WORKDIR /app
COPY . .
WORKDIR /app/social-log-service
RUN go build -o social-log-service .
CMD ["./social-log-service"]
