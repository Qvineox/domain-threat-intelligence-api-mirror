FROM golang:1.21.6 AS builder
LABEL authors="lysak.yaroslav00@yandex.ru"

# ref: https://habr.com/ru/companies/otus/articles/660301/

COPY . .

RUN go env -w CGO_ENABLED=0
RUN go env -w GOOS=linux
RUN go mod tidy

RUN mkdir /app_build

RUN go build -ldflags="-s -w" -o /app_build/go_build_stage.exe ./cmd

FROM alpine:3.19.1 as server

COPY --from=builder /app_build .

# TODO: add certificates
# TODO: add environment variables

CMD ["./go_build_stage.exe"]