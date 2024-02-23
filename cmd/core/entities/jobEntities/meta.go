package jobEntities

import "time"

type Metadata struct {
	UUID string

	Type     JobType
	Status   JobStatus
	Priority JobPriority
	Weight   int64

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

func NewMetadata(uuid string) {

}
