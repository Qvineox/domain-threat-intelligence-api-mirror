package jobEntities

import (
	"domain_threat_intelligence_api/api/grpc/protoServices"
	"domain_threat_intelligence_api/cmd/core/entities/userEntities"
	"fmt"
	"github.com/jackc/pgtype"
	"gorm.io/gorm"
	"time"
)

type Metadata struct {
	UUID *pgtype.UUID `json:"UUID" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`

	Type     JobType     `json:"Type" gorm:"column:type"`
	Status   JobStatus   `json:"Status" gorm:"column:status"`
	Priority JobPriority `json:"Priority" gorm:"column:priority"`
	Weight   int64       `json:"Weight" gorm:"column:weight"`

	TasksLeft uint64 `json:"TasksLeft,omitempty" gorm:"-"`

	CreatedBy   *userEntities.PlatformUser `json:"CreatedBy"`
	CreatedByID *uint64                    `json:"CreatedByID" gorm:"column:created_by_id"`

	StartedAt  *time.Time `json:"StartedAt" gorm:"column:started_at"`
	FinishedAt *time.Time `json:"FinishedAt" gorm:"column:finished_at"`

	Error string `json:"Error,omitempty" gorm:"column:error"`

	CreatedAt time.Time      `json:"CreatedAt"`
	UpdatedAt time.Time      `json:"UpdatedAt"`
	DeletedAt gorm.DeletedAt `json:"DeletedAt,omitempty" gorm:"index"`
}

type JobType uint64
type JobStatus uint64
type JobPriority uint64

const (
	JOB_TYPE_OSS JobType = iota
	JOB_TYPE_NMAP
	JOB_TYPE_WHOIS
	JOB_TYPE_DNS
	JOB_TYPE_DISCOVERY
	JOB_TYPE_SPIDER
)

const (
	JOB_STATUS_PENDING   JobStatus = iota // not yet started
	JOB_STATUS_STARTING                   // calculating tasks, creating required structures
	JOB_STATUS_WORKING                    // executing tasks
	JOB_STATUS_FINISHING                  // clearing and sending data
	JOB_STATUS_DONE                       // job finished execution and saved
	JOB_STATUS_ERROR                      // job stopped with error from API or scanners (can be multiple errors, with threshold)
	JOB_STATUS_PANIC                      // internal exception
	JOB_STATUS_CANCELLED                  // job was cancelled by user
)

const (
	JOB_PRIORITY_CRITICAL JobPriority = iota // job must be executed instantly
	JOB_PRIORITY_HIGH                        // job must be executed after current (stack mode)
	JOB_PRIORITY_MEDIUM                      // job should be executed with higher priority
	JOB_PRIORITY_LOW                         // job should be executed lastly in order (queue mode)

)

func (m *Metadata) ToProto() *protoServices.Meta {
	return &protoServices.Meta{
		Uuid:     fmt.Sprintf("%x", m.UUID.Bytes),
		Type:     protoServices.JobType(m.Type),
		Status:   protoServices.JobStatus(m.Status),
		Priority: protoServices.JobPriority(m.Priority),
		Weight:   m.Weight,
	}
}
