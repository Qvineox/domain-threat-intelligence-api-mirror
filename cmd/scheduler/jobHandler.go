package scheduler

import (
	"context"
	"domain_threat_intelligence_api/api/grpc/protoServices"
	"domain_threat_intelligence_api/cmd/core/entities/agentEntities"
	"domain_threat_intelligence_api/cmd/core/entities/jobEntities"
	"errors"
	"google.golang.org/grpc"
)

type jobHandler struct {
	MinPriority jobEntities.JobPriority
	IsBusy      bool

	currentJob *jobEntities.Job

	agent        *agentEntities.ScanAgent
	jobsClient   protoServices.JobsClient
	configClient protoServices.ConfigurationClient
	connClient   protoServices.ConnectionClient
}

func newJobHandler(agent *agentEntities.ScanAgent) (*jobHandler, error) {
	if agent == nil || !agent.IsActive || agent.Host == "" {
		return nil, errors.New("agent not available")
	}

	conn, err := grpc.Dial(agent.Host)
	if err != nil {
		return nil, errors.New("agent connection failed")
	}

	return &jobHandler{
		MinPriority:  agent.MinPriority,
		agent:        agent,
		jobsClient:   protoServices.NewJobsClient(conn),
		configClient: protoServices.NewConfigurationClient(conn),
		connClient:   protoServices.NewConnectionClient(conn),
	}, nil
}

func (h *jobHandler) assignJob(job *jobEntities.Job) error {
	if h.IsBusy || h.MinPriority > job.Meta.Priority {
		return errors.New("job cant be assigned to this handler")
	}

	// cleanup on assignment finish
	defer func() {
		h.currentJob = nil
		h.IsBusy = false
	}()

	h.currentJob = job
	h.IsBusy = true

	h.currentJob.Advance() // should move status to STARTING

	ctx := context.Background()

	_, err := h.jobsClient.StartJob(ctx, job.ToProto())
	if err != nil {
		h.currentJob.DoneWithError(err)
		return err
	}

	h.currentJob.Advance() // should move status to WORKING

	// TODO: listen stream from agent

	return nil
}
