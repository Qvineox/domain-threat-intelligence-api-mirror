package scheduler

import (
	"domain_threat_intelligence_api/cmd/core"
	"domain_threat_intelligence_api/cmd/core/entities/agentEntities"
	"domain_threat_intelligence_api/cmd/core/entities/jobEntities"
	"domain_threat_intelligence_api/cmd/scheduler/dialers"
	"errors"
	"fmt"
	"github.com/jackc/pgtype"
	"log/slog"
	"slices"
	"time"
)

type Scheduler struct {
	queue *jobEntities.Queue

	dialers []*dialers.ScanAgentDialer

	pollingRateMS time.Duration

	nodesRepo core.INetworkNodesRepo
	jobsRepo  core.IJobsRepo

	latestJobs []*jobEntities.Job

	quit chan bool
}

func NewScheduler(q *jobEntities.Queue, ar core.IAgentsRepo, nr core.INetworkNodesRepo, jr core.IJobsRepo, pr time.Duration) (*Scheduler, error) {
	slog.Info("creating scheduler...")
	sh := &Scheduler{
		queue:         q,
		pollingRateMS: pr,
		quit:          make(chan bool),
		nodesRepo:     nr,
		jobsRepo:      jr,
		latestJobs:    make([]*jobEntities.Job, 0),
	}

	// get all agents from database
	slog.Info("adding scanning agents...")
	agents, err := ar.SelectAllAgents()
	if err != nil {
		slog.Error("failed to load scanning agents: " + err.Error())
		panic(err)
	}

	for _, agent := range agents {
		err = sh.AddOrUpdateDialer(&agent)
		if err != nil {
			slog.Warn("failed to add agent handler: " + err.Error())
			return nil, err
		}
	}

	ac := len(sh.GetAllConnectedDialersUUIDs())
	if ac == 0 {
		slog.Warn("no scanning agent were added")
	} else {
		slog.Info(fmt.Sprintf("added %d scanning agents", ac))
	}

	return sh, nil
}

const latestJobsLifespanMinutes = 120

func (s *Scheduler) Start() {
	slog.Info(fmt.Sprintf("starting scheduler with polling rate %dms...", s.pollingRateMS))

	jobQueueTicker := time.NewTicker(s.pollingRateMS * time.Millisecond)
	queueStateTicker := time.NewTicker(s.pollingRateMS * time.Second)

	go func() {
		for {
			select {
			case <-jobQueueTicker.C:
				job := s.queue.Dequeue()
				if job != nil && job.Meta.Status != jobEntities.JOB_STATUS_CANCELLED {
					job.DequeuedTimes++

					_ = s.ScheduleJob(job)
				}
			case <-queueStateTicker.C:
				var latestJobs []*jobEntities.Job
				var threshold = time.Now()
				threshold = threshold.Add(-latestJobsLifespanMinutes * time.Minute)

				for _, j := range s.latestJobs {
					if j.Meta.Status < 4 || j.Meta.FinishedAt.After(threshold) {
						latestJobs = append(latestJobs, j)
					}
				}

				s.latestJobs = latestJobs
			case <-s.quit:
				slog.Warn("scheduler stopped")
				jobQueueTicker.Stop()
				return
			}
		}
	}()
}

func (s *Scheduler) Stop() {
	s.quit <- true
}

func (s *Scheduler) AddOrUpdateDialer(agent *agentEntities.ScanAgent) error {
	h, err := dialers.NewAgentDialer(agent, s.nodesRepo)
	if err != nil {
		return err
	}

	s.dialers = append(s.dialers, h) // TODO: can require mutex to be saved

	return nil
}

func (s *Scheduler) RemoveDialerByUUID(uuid pgtype.UUID) error {
	i := slices.IndexFunc(s.dialers, func(dialer *dialers.ScanAgentDialer) bool {
		return *dialer.Agent.UUID == uuid
	})

	if i == -1 {
		return errors.New("dialer with defined agent uuid not found in scheduler")
	}

	if s.dialers[i].IsBusy || s.dialers[i].Agent != nil {
		return errors.New("agent is busy")
	}

	slog.Warn(fmt.Sprintf("removing dialer for agent '%s' from scheduler", s.dialers[i].Agent.Name))
	s.dialers = slices.Delete(s.dialers, i, i+1)

	return nil
}

// ScheduleJob assigns Job to suitable JobHandler. If assignment fails, job is inserted in queue one more time
func (s *Scheduler) ScheduleJob(job *jobEntities.Job) error {
	if len(s.dialers) == 0 {
		slog.Warn("no agent dialers available for the job")
		_ = s.queue.Enqueue(job)

		return errors.New("no agent dialers available for the job")
	}

	for _, h := range s.dialers {
		if !h.IsBusy && job.Meta.Priority <= h.MinPriority {

			go func() {
				h.HandleOSSJob(job)

				job.Advance() // should move status to DONE

				err := s.jobsRepo.SaveJob(job)
				if err != nil {
					slog.Warn(fmt.Sprintf("failed to save ended job (%x): %s", job.Meta.UUID, err.Error()))
				}

				s.latestJobs = append(s.latestJobs, job)

				slog.Info(fmt.Sprintf("saved ended job (%x) with status %d", job.Meta.UUID, job.Meta.Status))
			}()

			return nil
		}
	}

	// if there are no available agents at the moment // TODO: add to config
	if job.DequeuedTimes <= 100 {
		_ = s.queue.Enqueue(job)
	}

	return nil
}

// CancelActiveJob finds active Job on agent and cancels it
func (s *Scheduler) CancelActiveJob(uuid pgtype.UUID) error {
	for _, d := range s.dialers {
		if d.CurrentJob != nil && *d.CurrentJob.Meta.UUID == uuid {
			d.CurrentJob.Meta.Status = jobEntities.JOB_STATUS_CANCELLED
			return nil
		}
	}

	return errors.New("job not found")
}

// GetAllJobs returns all jobs from queue and in active dialers. Also returns recently finished jobs.
func (s *Scheduler) GetAllJobs() [3][]*jobEntities.Job {
	var jobs [3][]*jobEntities.Job

	jobs[0] = s.queue.GetQueue()

	jobs[1] = make([]*jobEntities.Job, 0, len(s.dialers))
	for _, d := range s.dialers {
		if d.CurrentJob != nil {
			jobs[1] = append(jobs[1], d.CurrentJob)
		}
	}

	jobs[2] = s.latestJobs

	return jobs
}

// GetAllConnectedDialersUUIDs returns all jobs from queue and in active dialers
func (s *Scheduler) GetAllConnectedDialersUUIDs() []pgtype.UUID {
	var uuids = make([]pgtype.UUID, 0, len(s.dialers))

	for _, d := range s.dialers {
		uuids = append(uuids, *d.Agent.UUID)
	}

	return uuids
}
