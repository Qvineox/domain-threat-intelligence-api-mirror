package services

import (
	"domain_threat_intelligence_api/cmd/core"
	"domain_threat_intelligence_api/cmd/core/entities/jobEntities"
	"domain_threat_intelligence_api/cmd/scheduler"
	"errors"
	"github.com/jackc/pgtype"
)

type QueueServiceImpl struct {
	service core.IJobsService

	nodesRepo  core.INetworkNodesRepo
	agentsRepo core.IAgentsRepo

	queue     *jobEntities.Queue
	scheduler *scheduler.Scheduler
}

func NewQueueServiceImpl(s core.IJobsService, n core.INetworkNodesRepo, a core.IAgentsRepo, q *jobEntities.Queue, sh *scheduler.Scheduler) *QueueServiceImpl {
	go sh.Start()

	return &QueueServiceImpl{
		service:    s,
		nodesRepo:  n,
		agentsRepo: a,
		queue:      q,
		scheduler:  sh,
	}
}

func (q *QueueServiceImpl) QueueNewJob(params jobEntities.JobCreateParams) (*pgtype.UUID, error) {
	var job = &jobEntities.Job{}

	job.
		WithMetadata(params.Type, params.Priority, params.Weight, params.CreatedByUserID).
		WithPayload(params.Targets, params.Exceptions)

	switch job.Meta.Type {
	case jobEntities.JOB_TYPE_OSS:
		if len(params.OpenSourceProviders) == 0 {
			return nil, errors.New("providers not defined")
		}

		if params.Timout == 0 && params.Retries == 0 && params.Delay == 0 {
			job.WithOSSDirective(params.OpenSourceProviders, nil)
			break
		}

		if params.Retries < 1 {
			params.Retries = 1
		}

		if params.Timout < 5000 {
			params.Timout = 5000
		}

		job.WithOSSDirective(params.OpenSourceProviders, &jobEntities.DirectiveTimings{
			Timeout: params.Timout,
			Delay:   params.Delay,
			Reties:  params.Retries,
		})
	case jobEntities.JOB_TYPE_NMAP:
		return nil, errors.New("not implemented")
	case jobEntities.JOB_TYPE_WHOIS:
		return nil, errors.New("not implemented")
	case jobEntities.JOB_TYPE_DNS:
		return nil, errors.New("not implemented")
	case jobEntities.JOB_TYPE_DISCOVERY:
		return nil, errors.New("not implemented")
	case jobEntities.JOB_TYPE_SPIDER:
		return nil, errors.New("not implemented")
	}

	err := job.Validate()
	if err != nil {
		return nil, err
	}

	err = q.service.SaveJob(job)
	if err != nil {
		return nil, err
	}

	err = q.queue.Enqueue(job)
	if err != nil {
		return nil, err
	}

	return job.Meta.UUID, nil
}

func (q *QueueServiceImpl) AlterQueuedJob(uuid *pgtype.UUID, params jobEntities.JobCreateParams) (*pgtype.UUID, error) {
	// TODO implement me
	panic("implement me")
}

func (q *QueueServiceImpl) CancelQueuedJob(uuid *pgtype.UUID, force bool) error {
	var qErr, aErr error

	if force {
		qErr = q.scheduler.CancelActiveJob(*uuid)
	}

	aErr = q.queue.RemoveFromQueueByUUID(*uuid)

	if qErr != nil && aErr != nil {
		return aErr
	}

	return nil
}

func (q *QueueServiceImpl) RetrieveAllJobs() [3][]*jobEntities.Job {
	return q.scheduler.GetAllJobs()
}

func (q *QueueServiceImpl) RetrieveConnectedAgentsUUIDs() []pgtype.UUID {
	return q.scheduler.GetAllConnectedDialersUUIDs()
}
