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
	query := r.Model(&jobEntities.Job{})

	if filter.CreatedAfter != nil {
		query = query.Where("created_at > ?", filter.CreatedAfter)
	}

	if filter.CreatedBefore != nil {
		query = query.Where("created_at < ?", filter.CreatedBefore)
	}

	if filter.Priority != nil {
		query = query.Where("priority = ?", filter.Priority)
	}

	if filter.Status != nil {
		query = query.Where("status = ?", filter.Status)
	}

	if filter.CreatedBy != nil {
		query = query.Where("created_by_id = ?", filter.CreatedBy)
	}

	if len(filter.Types) > 0 {
		query = query.Where("type IN ?", filter.Types)
	}

	if filter.Limit != 0 {
		query = query.Limit(filter.Limit)
	}

	var result = make([]jobEntities.Job, 0)
	err := query.Preload("CreatedBy").Offset(filter.Offset).Order("created_at DESC, updated_at DESC, UUID DESC").Find(&result).Error

	for i := range result {
		_ = result[i].GetFieldsFromJSON()
	}

	return result, err
}

func (r *JobsRepoImpl) SelectJobByUUID(uuid pgtype.UUID) (jobEntities.Job, error) {
	var job jobEntities.Job

	err := r.Preload("CreatedBy").Preload("NodeScans").Preload("NodeScans.Node").Find(&job, uuid).Error

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
	query := r.Where("UUID = ?", uuid).Delete(&jobEntities.Job{})

	return query.RowsAffected, query.Error
}
