package client

import (
	"context"
	"domain_threat_intelligence_api/api/grpc/protoServices"
	"google.golang.org/grpc"
)

type ConnectionServiceImpl struct {
}

func (c *ConnectionServiceImpl) Hello(ctx context.Context, in *protoServices.SecurityToken, opts ...grpc.CallOption) (*protoServices.SecurityToken, error) {
	// TODO implement me
	panic("implement me")
}
