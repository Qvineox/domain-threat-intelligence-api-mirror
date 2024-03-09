package test

import (
	"domain_threat_intelligence_api/cmd/app"
	"domain_threat_intelligence_api/cmd/core/entities/jobEntities"
	"domain_threat_intelligence_api/cmd/core/repos"
	"domain_threat_intelligence_api/cmd/scheduler"
	"domain_threat_intelligence_api/configs"
	"fmt"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"testing"
	"time"
)

func TestScheduler(t *testing.T) {
	config, err := configs.NewTestConfig()
	require.NoError(t, err)

	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s database=%s sslmode=disable TimeZone=%s", config.Database.Host, config.Database.Port, config.Database.User, config.Database.Password, config.Database.Name, config.Database.Timezone)
	dbConn, err := gorm.Open(postgres.Open(dsn))

	err = app.Migrate(dbConn)
	require.NoError(t, err)

	jRepo := repos.NewJobsRepoImpl(dbConn)
	nRepo := repos.NewNetworkNodesRepoImpl(dbConn)

	var q = jobEntities.NewQueue(10)

	const pollingRageMS = 1000

	s, err := scheduler.NewScheduler(pollingRageMS, q, nRepo)
	require.NoError(t, err)

	go s.Start()

	t.Run("check no handlers job assignment", func(t *testing.T) {
		var job = &jobEntities.Job{}
		job.WithPayload([]string{"10.10.10.10/32", "ya.ru"}, []string{})
		job.WithMetadata(jobEntities.JOB_TYPE_OSS, jobEntities.JOB_PRIORITY_LOW, 10)
		job.WithOSSDirective([]jobEntities.SupportedOSSProvider{
			jobEntities.OSS_PROVIDER_IP_WHO_IS,
			jobEntities.OSS_PROVIDER_CROWD_SEC,
		}, &jobEntities.DirectiveTimings{
			Timeout: 10000,
			Delay:   100,
			Reties:  3,
		})

		require.NoError(t, job.Validate())
		err = jRepo.SaveJob(job)
		require.NoError(t, err)
		require.NotNil(t, job.Meta.UUID)

		err = s.ScheduleJob(job)
		require.Error(t, err)
	})

	t.Run("check no handlers job assignment from queue", func(t *testing.T) {
		var job = &jobEntities.Job{}
		job.WithPayload([]string{"20.20.20.20/32", "ya.ru"}, []string{})
		job.WithMetadata(jobEntities.JOB_TYPE_OSS, jobEntities.JOB_PRIORITY_LOW, 10)
		job.WithOSSDirective([]jobEntities.SupportedOSSProvider{
			jobEntities.OSS_PROVIDER_IP_WHO_IS,
			jobEntities.OSS_PROVIDER_CROWD_SEC,
		}, &jobEntities.DirectiveTimings{
			Timeout: 10000,
			Delay:   100,
			Reties:  3,
		})

		require.NoError(t, job.Validate())
		err = jRepo.SaveJob(job)
		require.NoError(t, err)
		require.NotNil(t, job.Meta.UUID)

		err = q.Enqueue(job)
		require.NoError(t, err)
	})

	t.Run("check queue state", func(t *testing.T) {
		time.Sleep(pollingRageMS * 2)

		jobs := q.GetQueue()

		require.Equal(t, jobs[0].Meta.Status, jobEntities.JOB_STATUS_PENDING)
		require.Equal(t, jobs[1].Meta.Status, jobEntities.JOB_STATUS_PENDING)

		require.Len(t, jobs, 2)
	})
}
