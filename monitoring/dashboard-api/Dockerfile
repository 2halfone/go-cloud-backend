FROM golang:1.23-alpine AS builder

WORKDIR /app
COPY monitoring/dashboard-api/go.mod monitoring/dashboard-api/go.sum ./
RUN go mod download

COPY monitoring/dashboard-api/. .
COPY ./shared ./shared
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

FROM alpine:latest
RUN apk --no-cache add ca-certificates curl tzdata
WORKDIR /root/
COPY --from=builder /app/main .
EXPOSE 3003
CMD ["./main"]
