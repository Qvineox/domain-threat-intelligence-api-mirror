package client

import (
	"context"
	"domain_threat_intelligence_api/api/proto/services"
	"google.golang.org/grpc"
)

type ConnectionServiceImpl struct {
}

func (c *ConnectionServiceImpl) Hello(ctx context.Context, in *services.SecurityToken, opts ...grpc.CallOption) (*services.SecurityToken, error) {
	// TODO implement me
	panic("implement me")
}
