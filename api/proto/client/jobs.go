package client

import (
	"context"
	"domain_threat_intelligence_api/api/proto/services"
	"google.golang.org/grpc"
)

type JobsServiceImpl struct {
}

func (j *JobsServiceImpl) StartJob(ctx context.Context, in *services.Job, opts ...grpc.CallOption) (services.Jobs_StartJobClient, error) {
	// TODO implement me
	panic("implement me")
}

func (j *JobsServiceImpl) TerminateJob(ctx context.Context, in *services.JobTermination, opts ...grpc.CallOption) (*services.None, error) {
	// TODO implement me
	panic("implement me")
}

func (j *JobsServiceImpl) RetrieveQueue(ctx context.Context, in *services.None, opts ...grpc.CallOption) (*services.Queue, error) {
	// TODO implement me
	panic("implement me")
}

func (j *JobsServiceImpl) RetrieveQueueStatus(ctx context.Context, in *services.None, opts ...grpc.CallOption) (*services.QueueStatus, error) {
	// TODO implement me
	panic("implement me")
}
