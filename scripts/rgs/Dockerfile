FROM artifactory.rgs.ru:5000/docker/golang:1.21.6-alpine3.19 AS builder
LABEL authors="Yaroslav_Lysak@rgs.ru"

RUN go env -w CGO_ENABLED=0
RUN go env -w GOOS=linux

COPY . /src
WORKDIR /src

RUN go mod tidy

RUN mkdir /app_build

RUN go build -ldflags="-s -w" -o /app_build/go_build_rgs.exe ./cmd

FROM artifactory.rgs.ru:5000/docker/alpine:3.19.1 as web_server

COPY --from=builder /app_build .
RUN mkdir configs

CMD ["./go_build_rgs.exe"]