# syntax=docker/dockerfile:1
FROM golang:1.24.3-alpine
WORKDIR /app
COPY . .
COPY ../shared ./shared
RUN go build -o social-log-service .
CMD ["./social-log-service"]
