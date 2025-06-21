# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /app

COPY shared/ ./shared/
COPY auth-service/ ./
COPY ./shared ./shared

# Tidy and download dependencies (go.sum will be generated)
RUN go mod tidy
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

# Final stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata curl
WORKDIR /root/

COPY --from=builder /app/main .

EXPOSE 3001

CMD ["./main"]
