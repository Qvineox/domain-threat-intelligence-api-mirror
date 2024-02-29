package scheduler

import (
	"context"
	"domain_threat_intelligence_api/api/grpc/protoServices"
	"domain_threat_intelligence_api/cmd/core"
	"domain_threat_intelligence_api/cmd/core/entities/agentEntities"
	"domain_threat_intelligence_api/cmd/core/entities/jobEntities"
	"domain_threat_intelligence_api/cmd/loggers"
	"domain_threat_intelligence_api/cmd/scheduler/jobHandlers"
	"errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"io"
	"log/slog"
	"sync"
)

type agentDialer struct {
	MinPriority jobEntities.JobPriority
	IsBusy      bool

	currentJob *jobEntities.Job

	agent        *agentEntities.ScanAgent
	jobsClient   protoServices.JobsClient
	configClient protoServices.ConfigurationClient
	connClient   protoServices.ConnectionClient

	logger loggers.SchedulerLogger

	repo core.INetworkNodesRepo
}

func newAgentDialer(agent *agentEntities.ScanAgent, repo core.INetworkNodesRepo) (*agentDialer, error) {
	if agent == nil || !agent.IsActive || agent.Host == "" {
		return nil, errors.New("agent not available")
	}

	// ref: https://grpc.io/docs/guides/wait-for-ready/
	// ref: https://stackoverflow.com/questions/45547278/how-to-wait-for-the-grpc-server-connection

	// TODO: adjust security options
	cc, err := grpc.Dial(agent.Host, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, errors.New("agent connection failed: " + err.Error())
	}

	state := cc.GetState()
	slog.Info(state.String())

	return &agentDialer{
		MinPriority:  agent.MinPriority,
		agent:        agent,
		jobsClient:   protoServices.NewJobsClient(cc),
		configClient: protoServices.NewConfigurationClient(cc),
		connClient:   protoServices.NewConnectionClient(cc),
		repo:         repo,
	}, nil
}

func (d *agentDialer) handleOSSJob(job *jobEntities.Job) error {
	if d.IsBusy || d.MinPriority > job.Meta.Priority {
		return errors.New("job cant be assigned to this handler")
	}

	// cleanup on assignment finish
	defer func() {
		d.currentJob = nil
		d.IsBusy = false
	}()

	d.currentJob = job
	d.IsBusy = true

	d.currentJob.Advance() // should move status to STARTING

	ctx := context.Background()

	// switch job types
	stream, err := d.jobsClient.StartOSS(ctx, job.ToProto())
	if err != nil {
		d.currentJob.DoneWithError(err)
		return err
	}

	// starting oss audit reports handling
	ch := make(chan *protoServices.TargetAuditReport, 1000)
	handler := jobHandlers.NewOSSJobHandler(d.agent, job, d.repo, ch)
	wg := &sync.WaitGroup{}

	go handler.Start(ctx, wg)

	d.currentJob.Advance() // should move status to WORKING

	for {
		var r *protoServices.TargetAuditReport

		r, err = stream.Recv()
		if err == io.EOF {
			close(ch)
			break
		} else if err != nil {
			d.logger.MessageError(job.Meta.UUID, d.agent.UUID, d.agent.Name, err)
		}

		wg.Add(1)
		ch <- r
	}

	wg.Wait()

	return nil
}
