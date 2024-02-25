package test

import (
	"domain_threat_intelligence_api/cmd/app"
	"domain_threat_intelligence_api/cmd/core/entities/jobEntities"
	"domain_threat_intelligence_api/cmd/core/repos"
	"domain_threat_intelligence_api/configs"
	"fmt"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"testing"
)

func TestQueue(t *testing.T) {
	config, err := configs.NewTestConfig()
	require.NoError(t, err)

	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s database=%s sslmode=disable TimeZone=%s", config.Database.Host, config.Database.Port, config.Database.User, config.Database.Password, config.Database.Name, config.Database.Timezone)
	dbConn, err := gorm.Open(postgres.Open(dsn))

	err = app.Migrate(dbConn)
	require.NoError(t, err)

	repo := repos.NewJobsRepoImpl(dbConn)

	const limit = 4
	jobReceiver := make(chan *jobEntities.Job, limit)
	queue := jobEntities.NewQueue(limit, jobReceiver)

	var job1 = &jobEntities.Job{}
	job1.WithPayload([]string{"10.10.10.10/32", "ya.ru"}, []string{})
	job1.WithMetadata(jobEntities.JOB_TYPE_OSS, jobEntities.JOB_PRIORITY_LOW, 10)
	job1.WithOSSDirective([]jobEntities.SupportedOSSProvider{
		jobEntities.OSS_PROVIDER_IP_WHO_IS,
		jobEntities.OSS_PROVIDER_CROWD_SEC,
	}, &jobEntities.DirectiveTimings{
		Timeout: 10000,
		Delay:   100,
		Reties:  3,
	})

	require.NoError(t, job1.Validate())
	err = repo.SaveJob(job1)
	require.NoError(t, err)
	require.NotNil(t, job1.Meta.UUID)

	t.Run("job repository checks", func(t *testing.T) {
		job, _ := repo.SelectJobByUUID(job1.Meta.UUID)

		require.Equal(t, job1.Meta.UUID, job.Meta.UUID)
		require.Equal(t, job1.Meta.Type, job.Meta.Type)
		require.Equal(t, job1.Meta.Priority, job.Meta.Priority)
		require.Equal(t, job1.Meta.Weight, job.Meta.Weight)
		require.Equal(t, job1.Meta.Status, job.Meta.Status)

		require.Equal(t, job1.Payload.Targets, job.Payload.Targets)
		require.Equal(t, job1.Payload.Exceptions, job.Payload.Exceptions)

		require.Equal(t, job1.Directives.OpenSourceScanDirectives.Providers, job.Directives.OpenSourceScanDirectives.Providers)
	})

	t.Run("job queuing", func(t *testing.T) {
		err := queue.Enqueue(job1)
		require.NoError(t, err)

		require.Len(t, queue.GetQueue(), 1)
	})

	var job2 = &jobEntities.Job{}
	job2.WithPayload([]string{"20.20.20.20/32", "mail.ru", "qvineox.ru"}, []string{})
	job2.WithMetadata(jobEntities.JOB_TYPE_OSS, jobEntities.JOB_PRIORITY_MEDIUM, 10)
	job2.WithOSSDirective([]jobEntities.SupportedOSSProvider{
		jobEntities.OSS_PROVIDER_VIRUS_TOTAL,
	}, &jobEntities.DirectiveTimings{
		Timeout: 10000,
		Delay:   100,
		Reties:  3,
	})

	var job3 = &jobEntities.Job{}
	job3.WithPayload([]string{"30.30.30.30/32", "google.com"}, []string{"8.8.8.8"})
	job3.WithMetadata(jobEntities.JOB_TYPE_OSS, jobEntities.JOB_PRIORITY_HIGH, 10)
	job3.WithOSSDirective([]jobEntities.SupportedOSSProvider{
		jobEntities.OSS_PROVIDER_CROWD_SEC,
		jobEntities.OSS_PROVIDER_IP_QUALITY_SCORE,
	}, &jobEntities.DirectiveTimings{
		Timeout: 10000,
		Delay:   100,
		Reties:  5,
	})

	require.NoError(t, job2.Validate())
	require.NoError(t, repo.SaveJob(job2))
	require.NotNil(t, job2.Meta.UUID)

	require.NoError(t, job3.Validate())
	require.NoError(t, repo.SaveJob(job3))
	require.NotNil(t, job3.Meta.UUID)

	t.Run("job further queuing", func(t *testing.T) {
		err := queue.Enqueue(job2)
		require.NoError(t, err)

		require.Len(t, queue.GetQueue(), 2)

		err = queue.Enqueue(job3)
		require.NoError(t, err)

		require.Len(t, queue.GetQueue(), 3)
	})

	t.Run("check priority order", func(t *testing.T) {
		q := queue.GetQueue()

		for _, j := range q {
			fmt.Printf("priority: %d | weight: %d\n", j.Meta.Priority, j.Meta.Weight)
		}

		require.Equal(t, q[0], job3)
		require.Equal(t, q[1], job2)
		require.Equal(t, q[2], job1)
	})

	var job4 = &jobEntities.Job{}
	job4.WithPayload([]string{"40.40.40.40/32", "vk.ru"}, []string{"4.4.4.4"})
	job4.WithMetadata(jobEntities.JOB_TYPE_OSS, jobEntities.JOB_PRIORITY_MEDIUM, 30)
	job4.WithOSSDirective([]jobEntities.SupportedOSSProvider{
		jobEntities.OSS_PROVIDER_SHODAN,
	}, &jobEntities.DirectiveTimings{
		Timeout: 20000,
		Delay:   200,
		Reties:  2,
	})

	require.NoError(t, job4.Validate())
	require.NoError(t, repo.SaveJob(job4))
	require.NotNil(t, job4.Meta.UUID)

	var job5 = &jobEntities.Job{}
	job5.WithPayload([]string{"50.50.50.50/32", "mirea.ru"}, []string{})
	job5.WithMetadata(jobEntities.JOB_TYPE_OSS, jobEntities.JOB_PRIORITY_CRITICAL, 20)
	job5.WithOSSDirective([]jobEntities.SupportedOSSProvider{
		jobEntities.OSS_PROVIDER_SHODAN,
	}, &jobEntities.DirectiveTimings{
		Timeout: 20000,
		Delay:   200,
		Reties:  2,
	})

	require.NoError(t, job5.Validate())
	require.NoError(t, repo.SaveJob(job5))
	require.NotNil(t, job5.Meta.UUID)

	t.Run("limit check", func(t *testing.T) {
		require.Equal(t, queue.GetLimit(), limit)

		require.NoError(t, queue.Enqueue(job4))
		require.Error(t, queue.Enqueue(job5))
	})

	t.Run("check priority reorder", func(t *testing.T) {
		q := queue.GetQueue()

		for _, j := range q {
			fmt.Printf("priority: %d | weight: %d\n", j.Meta.Priority, j.Meta.Weight)
		}

		require.Equal(t, q[0], job3)
		require.Equal(t, q[1], job2)
		require.Equal(t, q[2], job4)
		require.Equal(t, q[3], job1)
	})

	t.Run("check job status change", func(t *testing.T) {
		q := queue.GetQueue()

		for _, j := range q {
			j.Meta.Status = jobEntities.JOB_STATUS_CANCELLED
		}

		for _, j := range queue.GetQueue() {
			require.Equal(t, j.Meta.Status, jobEntities.JOB_STATUS_CANCELLED)
		}
	})

	t.Run("check dequeue", func(t *testing.T) {
		job := queue.Dequeue()

		require.Equal(t, job, job3)
		require.Len(t, queue.GetQueue(), 3)

		job = queue.Dequeue()

		require.Equal(t, job, job2)
		require.Len(t, queue.GetQueue(), 2)

		job = queue.Dequeue()

		require.Equal(t, job, job4)
		require.Len(t, queue.GetQueue(), 1)

		job = queue.Dequeue()

		require.Equal(t, job, job1)
		require.Len(t, queue.GetQueue(), 0)

		require.Nil(t, queue.Dequeue())
	})
}
