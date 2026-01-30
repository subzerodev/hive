# Dockerfile
FROM golang:1.25-alpine AS builder

# Install build dependencies for CGO (required by go-sqlite3)
RUN apk --no-cache add gcc musl-dev

WORKDIR /app
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -o hive .

FROM alpine:3.19

RUN apk --no-cache add ca-certificates
WORKDIR /app
COPY --from=builder /app/hive .
COPY static/ ./static/
COPY vulns/ ./vulns/

EXPOSE 8080
CMD ["./hive"]
