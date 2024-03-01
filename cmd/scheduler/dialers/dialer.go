package dialers

import (
	"context"
	"domain_threat_intelligence_api/api/grpc/protoServices"
	"domain_threat_intelligence_api/cmd/core"
	"domain_threat_intelligence_api/cmd/core/entities/agentEntities"
	"domain_threat_intelligence_api/cmd/core/entities/jobEntities"
	"domain_threat_intelligence_api/cmd/loggers"
	"errors"
	"fmt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"io"
	"log/slog"
	"sync"
)

type ScanAgentDialer struct {
	MinPriority   jobEntities.JobPriority
	IsBusy        bool
	IsAcceptsJobs bool

	CurrentJob *jobEntities.Job

	Agent        *agentEntities.ScanAgent
	jobsClient   protoServices.JobsClient
	configClient protoServices.ConfigurationClient
	connClient   protoServices.ConnectionClient

	logger loggers.DialerLogger

	repo core.INetworkNodesRepo
}

func NewAgentDialer(agent *agentEntities.ScanAgent, repo core.INetworkNodesRepo) (*ScanAgentDialer, error) {
	if agent == nil || !agent.IsActive || agent.Host == "" {
		return nil, errors.New("Agent not available")
	}

	// ref: https://grpc.io/docs/guides/wait-for-ready/
	// ref: https://stackoverflow.com/questions/45547278/how-to-wait-for-the-grpc-server-connection

	// TODO: adjust security options
	cc, err := grpc.Dial(agent.Host, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		slog.Error(fmt.Sprintf("failed to connected agent '%s' on %s", agent.Name, agent.Host))
		return nil, errors.New("Agent connection failed: " + err.Error())
	}

	slog.Info(fmt.Sprintf("successfully connected agent '%s' on %s", agent.Name, agent.Host))

	return &ScanAgentDialer{
		MinPriority:  agent.MinPriority,
		Agent:        agent,
		jobsClient:   protoServices.NewJobsClient(cc),
		configClient: protoServices.NewConfigurationClient(cc),
		connClient:   protoServices.NewConnectionClient(cc),
		repo:         repo,
		logger:       loggers.NewDialerLogger(agent.UUID, agent.Name),
	}, nil
}

func (d *ScanAgentDialer) HandleOSSJob(job *jobEntities.Job) {
	if d.IsBusy || d.MinPriority < job.Meta.Priority {
		err := errors.New("job cant be assigned to this dialer")
		d.logger.JobAssignmentFailed(job.Meta.UUID, err)

		return
	}

	// cleanup on assignment finish
	defer func() {
		d.CurrentJob = nil
		d.IsBusy = false
	}()

	d.CurrentJob = job
	d.IsBusy = true

	d.CurrentJob.Advance() // should move status to STARTING

	ctx := context.Background()

	// switch job types
	stream, err := d.jobsClient.StartOSS(ctx, job.ToProto())
	if err != nil {
		d.CurrentJob.DoneWithError(err)
		return
	}

	d.logger.JobAssigned(job.Meta.UUID)

	// starting oss audit reports handling
	ch := make(chan *protoServices.TargetAuditReport, 1000)
	handler := NewOSSJobHandler(d.Agent, job, d.repo, ch)
	wg := &sync.WaitGroup{}

	go handler.Start(ctx, wg)

	d.CurrentJob.Advance() // should move status to WORKING

	for {
		var r *protoServices.TargetAuditReport

		r, err = stream.Recv()
		if err == io.EOF {
			close(ch)
			break
		} else if err != nil {
			d.logger.MessageError(job.Meta.UUID, err)
		}

		wg.Add(1)
		ch <- r
	}

	wg.Wait()
	d.logger.JobFinished(job.Meta.UUID)
	d.CurrentJob.Advance()
}
