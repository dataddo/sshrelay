FROM golang:1.23 AS builder
LABEL maintainer="Tomas Prochazka <tomas.prochazka@dataddo.com>"
WORKDIR /app
ENV CGO_ENABLED=0
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build .

FROM gcr.io/distroless/static
LABEL maintainer="Tomas Prochazka <tomas.prochazka@dataddo.com>"
COPY --from=builder /app/sshrelay /bin/sshrelay
CMD ["/bin/sshrelay"]
