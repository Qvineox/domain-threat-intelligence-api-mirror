package jobEntities

import (
	"cmp"
	"errors"
	"github.com/jackc/pgtype"
	"slices"
	"sync"
)

type Queue struct {
	limit int

	// jobStore mirrors state of the queue, provides API to see queue state
	// jobStore map[pgtype.UUID]*Job

	queue []*Job

	// queue chan *Job

	mutex sync.Mutex
}

func NewQueue(limit int) *Queue {
	return &Queue{limit: limit, queue: make([]*Job, 0, limit)}
}

func (q *Queue) GetLimit() int {
	return q.limit
}

func (q *Queue) GetQueue() []*Job {
	return q.queue
}

// Enqueue inserts Job into Queue and reorders all Jobs by priority and weight
func (q *Queue) Enqueue(job *Job) error {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	if len(q.queue)+1 > q.limit {
		return errors.New("queue limit reached")
	}

	q.queue = append(q.queue, job)

	slices.SortFunc(q.queue, func(a, b *Job) int {
		if a.Meta.Priority == b.Meta.Priority {
			return cmp.Compare(a.Meta.Weight, b.Meta.Weight)
		}

		return cmp.Compare(a.Meta.Priority, b.Meta.Priority)
	})

	return nil
}

// Dequeue resolves first Job from Queue and deletes it
func (q *Queue) Dequeue() *Job {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	if len(q.queue) == 0 {
		return nil
	}

	job := q.queue[0]

	q.queue = slices.Delete(q.queue, 0, 1)

	return job
}

func (q *Queue) RemoveFromQueueByUUID(uuid pgtype.UUID) error {
	if len(q.queue) > 0 {
		defer q.mutex.Unlock()
		q.mutex.Lock()

		i := slices.IndexFunc(q.queue, func(job *Job) bool {
			return *job.Meta.UUID == uuid
		})

		if i == -1 {
			return errors.New("job not found")
		}

		q.queue[i].Meta.Status = JOB_STATUS_CANCELLED

		return nil
	}

	return errors.New("queue is empty")
}
