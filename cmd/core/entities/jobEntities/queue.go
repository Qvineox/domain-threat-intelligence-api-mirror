package jobEntities

import (
	"errors"
	"github.com/jackc/pgtype"
	"slices"
	"sync"
)

type Queue struct {
	limit int

	// jobs mirrors state of the queue, provides API to see queue state
	jobs []*Job

	queue chan *Job

	sync.Mutex
}

func NewQueue(limit int) *Queue {
	return &Queue{limit: limit, queue: make(chan *Job, limit), jobs: make([]*Job, 0, limit)}
}

func (q *Queue) GetLimit() int {
	return q.limit
}

func (q *Queue) GetQueue() []*Job {
	return q.jobs
}

func (q *Queue) Enqueue(job *Job) error {
	q.Mutex.Lock()

	if len(q.queue)+1 >= q.limit {
		return errors.New("queue limit reached")
	}

	q.jobs = append(q.jobs, job)

	q.Mutex.Unlock()

	return nil
}

func (q *Queue) Dequeue() {
	if len(q.jobs) > 0 {
		q.Mutex.Lock()

		q.queue <- q.jobs[0]
		q.jobs = slices.Delete(q.jobs, 0, 1)

		q.Mutex.Unlock()
	}
}

func (q *Queue) RemoveFromQueueByUUID(uuid pgtype.UUID) {
	if len(q.jobs) > 0 {
		q.Mutex.Lock()

		index := slices.IndexFunc(q.jobs, func(j *Job) bool {
			return j.Meta.UUID == uuid
		})

		if index != -1 {
			q.jobs = slices.Delete(q.jobs, index, index+1)
		}

		q.Mutex.Unlock()
	}
}
