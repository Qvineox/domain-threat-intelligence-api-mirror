package jobEntities

import (
	"domain_threat_intelligence_api/api/grpc/protoServices"
	"domain_threat_intelligence_api/cmd/core/entities/networkEntities"
	"errors"
	"gorm.io/datatypes"
	"reflect"
	"time"
)

type Job struct {
	Meta       *Metadata  `json:"Meta" gorm:"embedded"`
	Payload    Payload    `json:"Payload" gorm:"-"`
	Directives Directives `json:"Directives" gorm:"-"`

	// DirectivesJSON is marshalled from Directives via PrepareToSave
	DirectivesJSON datatypes.JSONType[Directives] `json:"-"  gorm:"column:directives"`

	// PayloadJSON is marshalled from Payload via PrepareToSave
	PayloadJSON datatypes.JSONType[Payload] `json:"-" gorm:"column:payload"`

	NodeScans []networkEntities.NetworkNodeScan `json:"NodeScans" gorm:"foreignKey:JobUUID"`

	DequeuedTimes uint64 `json:"DequeuedTimes" gorm:"-"`
}

func (j *Job) WithMetadata(t JobType, p JobPriority, w int64, createdBy *uint64) *Job {
	j.Meta = &Metadata{
		Type:        t,
		Status:      JOB_STATUS_PENDING,
		Priority:    p,
		Weight:      w,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		CreatedByID: createdBy,
	}

	return j
}

func (j *Job) WithPayload(targets, exceptions []string) *Job {
	j.Payload = NewPayload(targets, exceptions)

	return j
}

func (j *Job) WithOSSDirective(providers []SupportedOSSProvider, timings *DirectiveTimings) *Job {
	var t *DirectiveTimings

	if timings == nil {
		t = &DirectiveTimings{
			Timeout: defaultTimout,
			Delay:   defaultDelay,
			Reties:  defaultRetries,
		}
	} else {
		t = timings
	}

	j.Directives.OpenSourceScanDirectives = &OSSDirectives{
		Providers: providers,
		Timings:   t,
	}

	return j
}

func (j *Job) WithDiscoveryDirective(timings *DirectiveTimings) *Job {
	var t *DirectiveTimings

	if timings == nil {
		t = &DirectiveTimings{
			Timeout: defaultTimout,
			Delay:   defaultDelay,
			Reties:  defaultRetries,
		}
	} else {
		t = timings
	}

	j.Directives.DiscoveryDirectives = &DiscoveryDirectives{
		Timings: t,
	}

	return j
}

func (j *Job) Validate() error {
	if j.Meta == nil {
		return errors.New("required job content was not provided")
	}

	if len(j.Payload.Targets) == 0 {
		return errors.New("no job targets defined")
	}

	// check if all filed are nil
	v := reflect.ValueOf(j.Directives)

	for i := 0; i < v.NumField(); i++ {
		if v.Field(i).Interface() != nil {
			return nil
		}
	}

	return errors.New("at least one directive must be provided")
}

func (j *Job) Advance() {
	now := time.Now()
	j.Meta.UpdatedAt = now

	if j.Meta.Status < JOB_STATUS_DONE {
		j.Meta.Status += 1
	}

	if j.Meta.Status == JOB_STATUS_STARTING {
		j.Meta.StartedAt = &now
	} else if j.Meta.Status >= JOB_STATUS_DONE {
		j.Meta.FinishedAt = &now
	}
}

func (j *Job) Done() {
	now := time.Now()

	j.Meta.Status = JOB_STATUS_DONE

	j.Meta.FinishedAt = &now
	j.Meta.UpdatedAt = now
}

func (j *Job) DoneWithError(err error) {
	now := time.Now()

	j.Meta.Status = JOB_STATUS_ERROR
	j.Meta.Error = err.Error()

	j.Meta.FinishedAt = &now
	j.Meta.UpdatedAt = now
}

func (j *Job) ToProto() *protoServices.Job {
	return &protoServices.Job{
		Meta:       j.Meta.ToProto(),
		Payload:    j.Payload.ToProto(),
		Directives: j.Directives.ToProto(),
	}
}

func (j *Job) PrepareToSave() error {
	j.DirectivesJSON = datatypes.NewJSONType(j.Directives)
	j.PayloadJSON = datatypes.NewJSONType(j.Payload)

	return nil
}

func (j *Job) GetFieldsFromJSON() error {
	j.Directives = j.DirectivesJSON.Data()
	j.Payload = j.PayloadJSON.Data()

	return nil
}

const defaultTimout = 5000
const defaultDelay = 200
const defaultRetries = 3

type JobsSearchFilter struct {
	Types  []JobType  `json:"Type" form:"types[]" binding:"omitempty,dive,oneof=0 1 2 3 4 5"`
	Status *JobStatus `json:"Status" form:"status" binding:"omitempty,oneof=0 1 2 3 4 5 6"`

	Priority *JobPriority `json:"Priority" form:"priority" binding:"omitempty,oneof=0 1 2 3"`

	CreatedBy *uint64 `json:"CreatedByUserID"  form:"created_by"`

	IsFinished bool `json:"IsFinished" form:"is_finished"`

	CreatedAfter  *time.Time `json:"CreatedAfter" form:"created_after" time_format:"2006-01-02"`
	CreatedBefore *time.Time `json:"CreatedBefore" form:"created_before" time_format:"2006-01-02"`

	Offset int `json:"Offset" form:"offset"`
	Limit  int `json:"Limit" form:"limit" binding:"required"`
}

type JobCreateParams struct {
	Type     JobType     `json:"Type" binding:"oneof=0 1 2 3 4 5"`
	Priority JobPriority `json:"Priority" binding:"oneof=0 1 2 3"`
	Weight   int64       `json:"Weight,omitempty"`

	Targets    []string `json:"Targets" binding:"required"`
	Exceptions []string `json:"Exceptions,omitempty"`

	UseHomeBound bool `json:"UseHomeBound"`
	Private      bool `json:"Private"`

	CreatedByUserID *uint64 `json:"CreatedByUserID"`

	OpenSourceProviders []SupportedOSSProvider `json:"Providers,omitempty" binding:"dive,oneof=0 1 2 3 4"`

	Delay   uint64 `json:"Delay,omitempty"`
	Timout  uint64 `json:"Timout,omitempty"`
	Retries uint64 `json:"Retries,omitempty"`
}
