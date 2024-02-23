package jobEntities

import (
	"domain_threat_intelligence_api/api/grpc/protoServices"
	"fmt"
	"github.com/jackc/pgtype"
	"google.golang.org/protobuf/types/known/timestamppb"
	"time"
)

type Metadata struct {
	UUID pgtype.UUID `json:"UUID" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`

	Type     JobType
	Status   JobStatus
	Priority JobPriority
	Weight   int64

	// CreatedBy uint64

	CreatedAt  time.Time
	UpdatedAt  time.Time
	StartedAt  *time.Time
	FinishedAt *time.Time
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
	JOB_STATUS_ERROR                      // job stopped with error from API or scanners (can be multiple errors, with threshold)
	JOB_STATUS_PANIC                      // internal exception
)

const (
	JOB_PRIORITY_LOW      JobPriority = iota // job should be executed lastly in order (queue mode)
	JOB_PRIORITY_MEDIUM                      // job should be executed with higher priority
	JOB_PRIORITY_HIGH                        // job must be executed after current (stack mode)
	JOB_PRIORITY_CRITICAL                    // job must be executed instantly
)

func (m *Metadata) ToProto() *protoServices.Meta {
	return &protoServices.Meta{
		Uuid:      fmt.Sprintf("%x", m.UUID.Bytes),
		Type:      protoServices.JobType(m.Type),
		Status:    protoServices.JobStatus(m.Status),
		Priority:  protoServices.JobPriority(m.Priority),
		Weight:    m.Weight,
		CreatedAt: timestamppb.New(m.CreatedAt),
		UpdatedAt: timestamppb.New(m.CreatedAt),
	}
}
