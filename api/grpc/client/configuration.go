package client

import (
	"context"
	"domain_threat_intelligence_api/api/grpc/protoServices"
	"google.golang.org/grpc"
)

type ConfigurationServiceImpl struct {
}

func (c *ConfigurationServiceImpl) Reconfigure(ctx context.Context, in *protoServices.AgentConfig, opts ...grpc.CallOption) (*protoServices.AgentConfig, error) {
	// TODO implement me
	panic("implement me")
}

func (c *ConfigurationServiceImpl) RetrieveConfig(ctx context.Context, in *protoServices.None, opts ...grpc.CallOption) (*protoServices.AgentConfig, error) {
	// TODO implement me
	panic("implement me")
}
