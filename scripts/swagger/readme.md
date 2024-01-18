# Swagger documentation

This project uses Swagger Docs to describe and interact with the provided API.

Swagger docs are built with [Swag](https://github.com/swaggo/swag) tool for Golang.

## Development scripts

First, Swagger development tool has to be installed. Then use following script to generate documentation.

```shell
go env -w GOOS=windows

go install github.com/swaggo/swag/cmd/swag@latest
swag init --dir api/rest -g router.go --output docs/swagger -ot go,json --parseDependency
swag fmt
```

Swagger init command should be executed every time when API documentation changes. Also, to parse and format all model
dependencies flag `--parseDependency` should always be provided.

These scripts also can be executed in IDEA IDE with [idea](..%2Fidea) scripts.

With default config documentation page will be available on: http://localhost:7090/swagger/index.html#/