FROM golang:1.25 AS builder
LABEL maintainer="Tomas Karela Prochazka <tomas.prochazka@dataddo.com>"
WORKDIR /app
ENV CGO_ENABLED=0
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -ldflags="-X 'main.Version=$APP_VERSION'" .

FROM gcr.io/distroless/static
LABEL maintainer="Tomas Karela Prochazka <tomas.prochazka@dataddo.com>"
COPY --from=builder /app/sshrelay /bin/sshrelay
CMD ["/bin/sshrelay"]
