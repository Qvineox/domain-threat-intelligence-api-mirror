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
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"io"
	"log/slog"
	"sync"
)

type ScanAgentDialer struct {
	MinPriority jobEntities.JobPriority
	IsBusy      bool

	CurrentJob *jobEntities.Job

	Agent *agentEntities.ScanAgent

	connection *grpc.ClientConn

	jobsClient   protoServices.JobsClient
	configClient protoServices.ConfigurationClient
	connClient   protoServices.ConnectionClient

	logger loggers.DialerLogger

	repo core.INetworkNodesRepo
}

func NewAgentDialer(agent *agentEntities.ScanAgent, repo core.INetworkNodesRepo) (*ScanAgentDialer, error) {
	if agent == nil || agent.Host == "" {
		return nil, errors.New("agent not available")
	}

	a := &ScanAgentDialer{
		MinPriority: agent.MinPriority,
		Agent:       agent,
		repo:        repo,
		IsBusy:      false,
		logger:      loggers.NewDialerLogger(agent.UUID, agent.Name),
	}

	return a, nil
}

func (d *ScanAgentDialer) Connect(tls credentials.TransportCredentials) error {
	var err error

	// ref: https://grpc.io/docs/guides/wait-for-ready/
	// ref: https://stackoverflow.com/questions/45547278/how-to-wait-for-the-grpc-server-connection
	// ref: https://github.com/grpc/grpc-go/blob/master/examples/features/encryption/TLS/client/main.go (tls)

	if tls != nil {
		d.connection, err = grpc.Dial(d.Agent.Host, grpc.WithTransportCredentials(tls))
	} else {
		d.connection, err = grpc.Dial(d.Agent.Host, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	if err != nil {
		err = errors.New(fmt.Sprintf("failed to connect agent '%s' on %s: %s", d.Agent.Name, d.Agent.Host, err.Error()))

		d.logger.ConnectionError(connectivity.Shutdown, err)
		return err
	}

	d.jobsClient = protoServices.NewJobsClient(d.connection)
	d.configClient = protoServices.NewConfigurationClient(d.connection)
	d.connClient = protoServices.NewConnectionClient(d.connection)

	return nil
}

func (d *ScanAgentDialer) IsConnected() bool {
	if !d.Agent.IsActive || d.connection == nil {
		return false
	}

	state := d.connection.GetState()

	// try to reconnect
	if d.Agent.IsActive && state != connectivity.Ready && !d.IsBusy {
		d.connection.Connect()

		if state == connectivity.TransientFailure {
			d.connection.ResetConnectBackoff()
		}
	}

	return state == connectivity.Ready || state == connectivity.Idle
}

func (d *ScanAgentDialer) CanAcceptJobs() bool {
	return d.Agent.IsActive && d.IsConnected()
}

func (d *ScanAgentDialer) HandleOSSJob(job *jobEntities.Job) {
	if !d.IsConnected() {
		err := errors.New("agent is not connected")
		d.logger.JobAssignmentFailed(job.Meta.UUID, err)

		return
	}

	if d.IsBusy || d.MinPriority < job.Meta.Priority {
		err := errors.New("job cant be assigned: agent busy or priority too low")
		d.logger.JobAssignmentFailed(job.Meta.UUID, err)

		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	d.CurrentJob = job
	d.IsBusy = true

	// cleanup on assignment finish or recover
	defer func() {
		r := recover()

		if r != nil {
			slog.Error("dialer recovered with error: " + r.(string))
			job.Meta.Status = jobEntities.JOB_STATUS_PANIC
		}

		d.CurrentJob = nil
		d.IsBusy = false

		cancel()
	}()

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

		if d.CurrentJob.Meta.Status == jobEntities.JOB_STATUS_CANCELLED {
			d.logger.JobCancel(job.Meta.UUID)
			break
		}

		r, err = stream.Recv()
		if err == io.EOF {
			close(ch)
			break
		} else if err != nil {
			d.logger.MessageError(job.Meta.UUID, err)
		}

		if r == nil {
			d.logger.MessageError(job.Meta.UUID, errors.New("received empty response"))
			job.Meta.Status = jobEntities.JOB_STATUS_ERROR
			break
		}

		wg.Add(1)
		d.CurrentJob.Meta.TasksLeft = r.TasksLeft

		ch <- r
	}

	wg.Wait()
	d.logger.JobFinished(job.Meta.UUID)
	d.CurrentJob.Advance() // // should move status to FINISHING
}
