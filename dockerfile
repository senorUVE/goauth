
FROM golang:1.16 as builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY app/authservice.go authservice.go
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o authservice .
FROM scratch
COPY --from=builder /app/authservice .
EXPOSE 8000
CMD ["./authservice"]
