package services

import (
	"domain_threat_intelligence_api/cmd/core"
	"domain_threat_intelligence_api/cmd/core/entities/jobEntities"
	"github.com/jackc/pgtype"
)

type JobsServiceImpl struct {
	repo core.IJobsRepo
}

func NewJobsServiceImpl(repo core.IJobsRepo) *JobsServiceImpl {
	return &JobsServiceImpl{repo: repo}
}

func (s *JobsServiceImpl) RetrieveJobsByFilter(filter jobEntities.JobsSearchFilter) ([]jobEntities.Job, error) {
	return s.repo.SelectJobsByFilter(filter)
}

func (s *JobsServiceImpl) RetrieveJobByUUID(uuid pgtype.UUID) (jobEntities.Job, error) {
	return s.repo.SelectJobByUUID(uuid)
}

func (s *JobsServiceImpl) SaveJob(job jobEntities.Job) (jobEntities.Job, error) {
	return s.repo.SaveJob(job)
}

func (s *JobsServiceImpl) DeleteJob(uuid pgtype.UUID) (int64, error) {
	return s.repo.DeleteJob(uuid)
}
