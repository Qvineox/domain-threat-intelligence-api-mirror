package repos

import (
	"domain_threat_intelligence_api/cmd/core/entities/jobEntities"
	"github.com/jackc/pgtype"
	"gorm.io/gorm"
)

type JobsRepoImpl struct {
	*gorm.DB
}

func NewJobsRepoImpl(DB *gorm.DB) *JobsRepoImpl {
	return &JobsRepoImpl{DB: DB}
}

func (r *JobsRepoImpl) SelectJobsByFilter(filter jobEntities.JobsSearchFilter) ([]jobEntities.Job, error) {
	var jobs = make([]jobEntities.Job, 0)

	// query := r.Model(&jobEntities.Job{})

	return jobs, nil
}

func (r *JobsRepoImpl) SelectJobByUUID(uuid pgtype.UUID) (jobEntities.Job, error) {
	var job jobEntities.Job

	err := r.Find(&job, uuid).Error

	job.Payload = job.PayloadJSON.Data()
	job.Directives = job.DirectivesJSON.Data()

	return job, err
}

func (r *JobsRepoImpl) SaveJob(job *jobEntities.Job) error {
	err := job.PrepareToSave()
	if err != nil {
		return err
	}

	err = r.Save(&job).Error

	return err
}

func (r *JobsRepoImpl) DeleteJob(uuid pgtype.UUID) (int64, error) {
	// TODO implement me
	panic("implement me")
}
