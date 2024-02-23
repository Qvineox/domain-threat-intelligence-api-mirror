package jobEntities

import (
	"domain_threat_intelligence_api/api/grpc/protoServices"
	"errors"
	"gorm.io/datatypes"
	"reflect"
	"time"
)

type Job struct {
	Meta       *Metadata  `json:"Meta" gorm:"embedded"`
	Payload    *Payload   `json:"Payload" gorm:"-"`
	Directives Directives `json:"Directives" gorm:"-"`

	// DirectivesJSON is marshalled from Directives via PrepareToSave
	DirectivesJSON datatypes.JSONType[Directives] `json:"-"  gorm:"column:directives"`

	// PayloadJSON is marshalled from Payload via PrepareToSave
	PayloadJSON datatypes.JSONType[Payload] `json:"-"  gorm:"column:payload"`
}

func (j *Job) WithMetadata(t JobType, p JobPriority, w int64) *Job {
	j.Meta = &Metadata{
		Type:      t,
		Status:    JOB_STATUS_PENDING,
		Priority:  p,
		Weight:    w,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
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
	if j.Meta == nil || j.Payload == nil {
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

func (j *Job) ToProto() *protoServices.Job {
	return &protoServices.Job{
		Meta:       j.Meta.ToProto(),
		Payload:    j.Payload.ToProto(),
		Directives: j.Directives.ToProto(),
	}
}

func (j *Job) PrepareToSave() error {
	err := j.DirectivesJSON.Scan(j.Directives)
	if err != nil {
		return err
	}

	err = j.PayloadJSON.Scan(j.Payload)
	if err != nil {
		return err
	}

	return nil
}

const defaultTimout = 5000
const defaultDelay = 200
const defaultRetries = 3

type JobsSearchFilter struct {
}

type JobCreateParams struct {
}
