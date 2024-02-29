package client

import (
	"context"
	"domain_threat_intelligence_api/api/grpc/protoServices"
	"google.golang.org/grpc"
)

type JobsClientImpl struct {
}

func (j *JobsClientImpl) StartOSS(ctx context.Context, in *protoServices.Job, opts ...grpc.CallOption) (protoServices.Jobs_StartOSSClient, error) {
	//TODO implement me
	panic("implement me")
}
