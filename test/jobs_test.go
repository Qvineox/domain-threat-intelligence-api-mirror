package test

import (
	"domain_threat_intelligence_api/cmd/core/entities/jobEntities"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestJob(t *testing.T) {
	job := jobEntities.Job{}

	t.Run("empty validation", func(t *testing.T) {
		require.Error(t, job.Validate())
	})

	t.Run("metadata assignment", func(t *testing.T) {
		job.WithMetadata(jobEntities.JOB_TYPE_OSS, jobEntities.JOB_PRIORITY_MEDIUM, 10)

		require.Equal(t, int64(10), job.Meta.Weight)
		require.Equal(t, jobEntities.JOB_TYPE_OSS, job.Meta.Type)
		require.Equal(t, jobEntities.JOB_PRIORITY_MEDIUM, job.Meta.Priority)

		require.Error(t, job.Validate())

		job.WithPayload(nil, nil)
		require.Error(t, job.Validate())
	})

	t.Run("targets type assignment", func(t *testing.T) {
		targets := []string{
			"10.10.10.10",
			"10.10.10.10/32",
			"10.10.10.10/21",
			"10.10.10.10/121", // incorrect mask
			"//test.com",
			"test.com",
			"//test.com/path",
			"test.com/path",    // no schema for URL
			"10.10.10.10/path", // no schema for URL
			"//10.10.10.10/path",
			"test@test.com",
			"test@test.com/path", // incorrect email
			"https://10.10.10.10/path",
			"http://10.10.10.10/path",
			"ftp://10.10.10.10/path",
			"https://10.10.10.10",
			"https://10.10.10.10?test=test",
			"www.text.com",
			"www.text.com/path", // no schema for URL
		}

		job.WithPayload(targets, []string{})

		require.Len(t, job.Payload.Targets, 15)

		require.Equal(t, job.Payload.Targets[0].Type, jobEntities.HOST_TYPE_CIDR)
		require.Equal(t, job.Payload.Targets[1].Type, jobEntities.HOST_TYPE_CIDR)
		require.Equal(t, job.Payload.Targets[2].Type, jobEntities.HOST_TYPE_CIDR)
		require.Equal(t, job.Payload.Targets[3].Type, jobEntities.HOST_TYPE_URL)
		require.Equal(t, job.Payload.Targets[4].Type, jobEntities.HOST_TYPE_DOMAIN)
		require.Equal(t, job.Payload.Targets[5].Type, jobEntities.HOST_TYPE_URL)
		require.Equal(t, job.Payload.Targets[6].Type, jobEntities.HOST_TYPE_URL)
		require.Equal(t, job.Payload.Targets[7].Type, jobEntities.HOST_TYPE_EMAIL)
		require.Equal(t, job.Payload.Targets[8].Type, jobEntities.HOST_TYPE_EMAIL)
		require.Equal(t, job.Payload.Targets[9].Type, jobEntities.HOST_TYPE_URL)
		require.Equal(t, job.Payload.Targets[10].Type, jobEntities.HOST_TYPE_URL)
		require.Equal(t, job.Payload.Targets[11].Type, jobEntities.HOST_TYPE_URL)
		require.Equal(t, job.Payload.Targets[12].Type, jobEntities.HOST_TYPE_URL)
		require.Equal(t, job.Payload.Targets[13].Type, jobEntities.HOST_TYPE_URL)
		require.Equal(t, job.Payload.Targets[14].Type, jobEntities.HOST_TYPE_DOMAIN)
	})

	t.Run("targets type reassignment", func(t *testing.T) {
		targets := []string{
			"10.10.10.10/32",
			"https://www.test.com",
			"www.test.com",
			"test@test.com",
		}

		job.WithPayload(targets, []string{})

		require.Len(t, job.Payload.Targets, 4)

		require.Equal(t, job.Payload.Targets[0].Type, jobEntities.HOST_TYPE_CIDR)
		require.Equal(t, job.Payload.Targets[1].Type, jobEntities.HOST_TYPE_URL)
		require.Equal(t, job.Payload.Targets[2].Type, jobEntities.HOST_TYPE_DOMAIN)
		require.Equal(t, job.Payload.Targets[3].Type, jobEntities.HOST_TYPE_EMAIL)
	})

	t.Run("targets type reassignment with exceptions", func(t *testing.T) {
		targets := []string{
			"10.10.10.10/32",
			"https://www.test.com",
			"www.test.com",
			"test@test.com",
		}

		exceptions := []string{
			"10.10.10.10/16",
			"www.test.com",
		}

		job.WithPayload(targets, exceptions)

		require.Len(t, job.Payload.Targets, 4)
		require.Len(t, job.Payload.Exceptions, 2)

		require.Equal(t, job.Payload.Targets[0].Type, jobEntities.HOST_TYPE_CIDR)
		require.Equal(t, job.Payload.Targets[1].Type, jobEntities.HOST_TYPE_URL)
		require.Equal(t, job.Payload.Targets[2].Type, jobEntities.HOST_TYPE_DOMAIN)
		require.Equal(t, job.Payload.Targets[3].Type, jobEntities.HOST_TYPE_EMAIL)

		require.Equal(t, job.Payload.Exceptions[0].Type, jobEntities.HOST_TYPE_CIDR)
		require.Equal(t, job.Payload.Exceptions[1].Type, jobEntities.HOST_TYPE_DOMAIN)
	})

	t.Run("directives assignment", func(t *testing.T) {
		job.WithOSSDirective([]jobEntities.SupportedOSSProvider{
			jobEntities.OSS_PROVIDER_CROWD_SEC,
			jobEntities.OSS_PROVIDER_VIRUS_TOTAL,
		}, nil)

		require.Len(t, job.Directives.OpenSourceScanDirectives.Providers, 2)
		require.NotNil(t, job.Directives.OpenSourceScanDirectives.Timings)

		require.Nil(t, job.Directives.DNSDirectives)
		require.Nil(t, job.Directives.DiscoveryDirectives)
		require.Nil(t, job.Directives.NMAPDirectives)
		require.Nil(t, job.Directives.WhoISDirectives)
		require.Nil(t, job.Directives.SpiderDirectives)
	})

	t.Run("directives reassignment with timings", func(t *testing.T) {
		const delay, timeout, retries = uint64(500), uint64(100), uint64(5)

		job.WithOSSDirective([]jobEntities.SupportedOSSProvider{
			jobEntities.OSS_PROVIDER_CROWD_SEC,
			jobEntities.OSS_PROVIDER_VIRUS_TOTAL,
			jobEntities.OSS_PROVIDER_IP_WHO_IS,
		}, &jobEntities.DirectiveTimings{
			Timeout: timeout,
			Delay:   delay,
			Reties:  retries,
		})

		require.Len(t, job.Directives.OpenSourceScanDirectives.Providers, 3)
		require.NotNil(t, job.Directives.OpenSourceScanDirectives.Timings)

		require.Equal(t, job.Directives.OpenSourceScanDirectives.Timings.Delay, delay)
		require.Equal(t, job.Directives.OpenSourceScanDirectives.Timings.Timeout, timeout)
		require.Equal(t, job.Directives.OpenSourceScanDirectives.Timings.Reties, retries)
	})

	t.Run("additional directives type assignment", func(t *testing.T) {
		job.WithDiscoveryDirective(nil)

		require.NotNil(t, job.Directives.DiscoveryDirectives)
		require.NotNil(t, job.Directives.DiscoveryDirectives.Timings)

		require.NotNil(t, job.Directives.OpenSourceScanDirectives)
		require.Len(t, job.Directives.OpenSourceScanDirectives.Providers, 3)

		require.Nil(t, job.Directives.DNSDirectives)
		require.Nil(t, job.Directives.NMAPDirectives)
		require.Nil(t, job.Directives.WhoISDirectives)
		require.Nil(t, job.Directives.SpiderDirectives)
	})

	t.Run("job validation", func(t *testing.T) {
		err := job.Validate()
		if err != nil {
			require.NoError(t, err)
		}
	})
}
