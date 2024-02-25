package services

import (
	"domain_threat_intelligence_api/cmd/core"
	"domain_threat_intelligence_api/cmd/core/entities/jobEntities"
	"errors"
	"github.com/jackc/pgtype"
)

type QueueServiceImpl struct {
	service core.IJobsService

	queue *jobEntities.Queue
}

func NewQueueServiceImpl(service core.IJobsService) *QueueServiceImpl {
	const limit = 1000

	jobChannel := make(chan *jobEntities.Job, limit)

	q := jobEntities.NewQueue(limit, jobChannel)

	return &QueueServiceImpl{service: service, queue: q}
}

func (q *QueueServiceImpl) QueueNewJob(params jobEntities.JobCreateParams) (pgtype.UUID, error) {
	var job = &jobEntities.Job{}

	job.
		WithMetadata(params.Type, params.Priority, params.Weight).
		WithPayload(params.Targets, params.Exceptions)

	switch job.Meta.Type {
	case jobEntities.JOB_TYPE_OSS:
		if len(params.OpenSourceProviders) == 0 {
			return pgtype.UUID{}, errors.New("providers not defined")
		}

		if params.Timout == 0 && params.Retries == 0 && params.Delay == 0 {
			job.WithOSSDirective(params.OpenSourceProviders, nil)
			break
		}

		if params.Retries == 0 {
			params.Retries = 1
		}

		if params.Timout == 0 {
			params.Timout = 5000
		}

		job.WithOSSDirective(params.OpenSourceProviders, &jobEntities.DirectiveTimings{
			Timeout: params.Timout,
			Delay:   params.Delay,
			Reties:  params.Retries,
		})
	case jobEntities.JOB_TYPE_NMAP:
		return pgtype.UUID{}, errors.New("not implemented")
	case jobEntities.JOB_TYPE_WHOIS:
		return pgtype.UUID{}, errors.New("not implemented")
	case jobEntities.JOB_TYPE_DNS:
		return pgtype.UUID{}, errors.New("not implemented")
	case jobEntities.JOB_TYPE_DISCOVERY:
		return pgtype.UUID{}, errors.New("not implemented")
	case jobEntities.JOB_TYPE_SPIDER:
		return pgtype.UUID{}, errors.New("not implemented")
	}

	err := job.Validate()
	if err != nil {
		return pgtype.UUID{}, err
	}

	err = q.service.SaveJob(job)
	if err != nil {
		return pgtype.UUID{}, err
	}

	err = q.queue.Enqueue(job)
	if err != nil {
		return pgtype.UUID{}, err
	}

	return job.Meta.UUID, nil
}

func (q *QueueServiceImpl) AlterQueuedJob(uuid pgtype.UUID, params jobEntities.JobCreateParams) (pgtype.UUID, error) {
	// TODO implement me
	panic("implement me")
}

func (q *QueueServiceImpl) CancelQueuedJob(uuid pgtype.UUID, force bool) error {
	// TODO implement me
	panic("implement me")
}

func (q *QueueServiceImpl) RetrieveQueuedJobs() ([]*jobEntities.Job, error) {
	return q.queue.GetQueue(), nil
}
