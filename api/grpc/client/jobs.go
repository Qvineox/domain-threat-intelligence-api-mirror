package client

import (
	"context"
	"domain_threat_intelligence_api/api/grpc/protoServices"
	"google.golang.org/grpc"
)

type JobsServiceImpl struct {
}

func (j *JobsServiceImpl) StartJob(ctx context.Context, in *protoServices.Job, opts ...grpc.CallOption) (protoServices.Jobs_StartJobClient, error) {
	// TODO implement me
	panic("implement me")
}

func (j *JobsServiceImpl) TerminateJob(ctx context.Context, in *protoServices.JobTermination, opts ...grpc.CallOption) (*protoServices.None, error) {
	// TODO implement me
	panic("implement me")
}

func (j *JobsServiceImpl) RetrieveQueue(ctx context.Context, in *protoServices.None, opts ...grpc.CallOption) (*protoServices.Queue, error) {
	// TODO implement me
	panic("implement me")
}

func (j *JobsServiceImpl) RetrieveQueueStatus(ctx context.Context, in *protoServices.None, opts ...grpc.CallOption) (*protoServices.QueueStatus, error) {
	// TODO implement me
	panic("implement me")
}
