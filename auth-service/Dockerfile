# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /app
COPY shared/ ./shared/
COPY auth-service/go.mod auth-service/go.sum ./
RUN go mod download

COPY auth-service/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

# Final stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata curl
WORKDIR /root/

COPY --from=builder /app/main .

EXPOSE 3001

CMD ["./main"]
