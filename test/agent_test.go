package test

// func TestAgent(t *testing.T) {
// 	config, err := configs.NewTestConfig()
// 	require.NoError(t, err)
//
// 	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s database=%s sslmode=disable TimeZone=%s", config.Database.Host, config.Database.Port, config.Database.User, config.Database.Password, config.Database.Name, config.Database.Timezone)
// 	dbConn, err := gorm.Open(postgres.Open(dsn))
//
// 	err = app.Migrate(dbConn)
// 	require.NoError(t, err)
//
// 	jRepo := repos.NewJobsRepoImpl(dbConn)
// 	nRepo := repos.NewNetworkNodesRepoImpl(dbConn)
//
// 	var q = jobEntities.NewQueue(10)
//
// 	const pollingRageMS = 1000
//
// 	s, err := scheduler.NewScheduler(pollingRageMS, q, nRepo)
// 	require.NoError(t, err)
//
// 	go s.Start()
//
// 	t.Run("create test handler", func(t *testing.T) {
// 		now := time.Now()
// 		ip := net.ParseIP("0.0.0.0:2814")
//
// 		err = s.AddDialer(&agentEntities.ScanAgent{
// 			UUID: nil,
// 			Name: "test agent",
// 			IPAddress: pgtype.Inet{
// 				IPNet: &net.IPNet{
// 					IP: ip,
// 				},
// 				Status: 0,
// 			},
// 			Host:          "localhost:2814",
// 			IsActive:      true,
// 			IsHomeBound:   true,
// 			Description:   "test agent",
// 			MinPriority:   jobEntities.JOB_PRIORITY_LOW,
// 			Config:        datatypes.JSONType[agentEntities.ScanAgentConfig]{},
// 			SecurityToken: "test_token", // TODO: check connection process
// 			CreatedAt:     now,
// 			UpdatedAt:     now,
// 		})
//
// 		require.NoError(t, err)
//
// 		t.Log("agent connected")
// 	})
//
// 	t.Run("pass job to handler", func(t *testing.T) {
// 		var job = &jobEntities.Job{}
// 		job.WithPayload([]string{"10.10.10.10/32", "ya.ru"}, []string{})
// 		job.WithMetadata(jobEntities.JOB_TYPE_OSS, jobEntities.JOB_PRIORITY_LOW, 10)
// 		job.WithOSSDirective([]jobEntities.SupportedOSSProvider{
// 			jobEntities.OSS_PROVIDER_VIRUS_TOTAL,
// 			jobEntities.OSS_PROVIDER_IP_QUALITY_SCORE,
// 		}, &jobEntities.DirectiveTimings{
// 			Timeout: 10000,
// 			Delay:   100,
// 			Reties:  3,
// 		})
//
// 		require.NoError(t, job.Validate())
// 		err = jRepo.SaveJob(job)
// 		require.NoError(t, err)
// 		require.NotNil(t, job.Meta.UUID)
//
// 		err = s.ScheduleJob(job)
// 		require.NoError(t, err)
// 	})
// }
