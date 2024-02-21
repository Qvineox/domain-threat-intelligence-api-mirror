package client

import (
	"context"
	"domain_threat_intelligence_api/api/proto/services"
	"google.golang.org/grpc"
)

type ConfigurationServiceImpl struct {
}

func (c *ConfigurationServiceImpl) Reconfigure(ctx context.Context, in *services.AgentConfig, opts ...grpc.CallOption) (*services.AgentConfig, error) {
	// TODO implement me
	panic("implement me")
}

func (c *ConfigurationServiceImpl) RetrieveConfig(ctx context.Context, in *services.None, opts ...grpc.CallOption) (*services.AgentConfig, error) {
	// TODO implement me
	panic("implement me")
}
