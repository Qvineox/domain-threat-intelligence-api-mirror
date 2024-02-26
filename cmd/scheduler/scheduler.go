package scheduler

import (
	"domain_threat_intelligence_api/cmd/core/entities/agentEntities"
	"domain_threat_intelligence_api/cmd/core/entities/jobEntities"
	"domain_threat_intelligence_api/cmd/loggers"
	"errors"
	"log/slog"
	"time"
)

type Scheduler struct {
	queue *jobEntities.Queue

	handlers []*jobHandler

	pollingRateMS time.Duration

	logger *loggers.SchedulerLogger

	quit chan bool
}

func NewScheduler(pollingRateMS time.Duration, queue *jobEntities.Queue) (*Scheduler, error) {
	return &Scheduler{
		queue:         queue,
		pollingRateMS: pollingRateMS,
		logger:        loggers.NewSchedulerLogger(),
		quit:          make(chan bool),
	}, nil
}

func (s *Scheduler) Start() {
	ticker := time.NewTicker(s.pollingRateMS * time.Millisecond)

	go func() {
		for {
			select {
			case <-ticker.C:
				slog.Debug("tick")

				job := s.queue.Dequeue()
				if job != nil {
					_ = s.AssignJobHandler(job)
				}

			case <-s.quit:
				ticker.Stop()
				return
			}
		}
	}()
}

func (s *Scheduler) Stop() {
	s.quit <- true
}

func (s *Scheduler) AddHandler(agent *agentEntities.ScanAgent) error {
	h, err := newJobHandler(agent)
	if err != nil {
		return err
	}

	s.handlers = append(s.handlers, h) // TODO: can require mutex to be saved

	return nil
}

// AssignJobHandler assigns Job to suitable JobHandler. If assignment fails, job is inserted in queue one more time
func (s *Scheduler) AssignJobHandler(job *jobEntities.Job) error {
	if len(s.handlers) == 0 {
		s.logger.NoHandlersAvailable(job.Meta.UUID)
		_ = s.queue.Enqueue(job)

		return errors.New("no handlers")
	}

	for _, h := range s.handlers {
		if !h.IsBusy && job.Meta.Priority >= h.MinPriority {
			err := h.assignJob(job)
			if err != nil {
				s.logger.JobAssignmentFailed(job.Meta.UUID, h.agent.UUID, h.agent.Name, err)

				_ = s.queue.Enqueue(job)

				return err
			}

			s.logger.JobAssigned(job.Meta.UUID, h.agent.UUID, h.agent.Name)
		}
	}

	return nil
}
