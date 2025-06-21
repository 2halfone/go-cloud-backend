# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Copy shared module
COPY shared/ ./shared/

# Copy gateway files
COPY gateway/ ./
COPY ./shared ./shared

# 7Tidy and download dependencies (go.sum will be generated)
RUN go mod tidy
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

# Final stage
FROM alpine:latest
RUN apk --no-cache add ca-certificates tzdata curl

WORKDIR /root/

COPY --from=builder /app/main .

CMD ["./main"]
