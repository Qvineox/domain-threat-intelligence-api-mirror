# Контракты gRPC

Для генерации кода для контрактов необходимо использовать следующие скрипты:

```shell

protoc --proto_path=./api/proto/contracts --go_out=./api/proto/services --go_opt=paths=source_relative --go-grpc_out=./api/proto/services --go-grpc_opt=paths=source_relative  agent.proto

```