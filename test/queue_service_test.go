package test

// func TestQueueService(t *testing.T) {
// 	config, err := configs.NewTestConfig()
// 	require.NoError(t, err)
//
// 	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s database=%s sslmode=disable TimeZone=%s", config.Database.Host, config.Database.Port, config.Database.User, config.Database.Password, config.Database.Name, config.Database.Timezone)
// 	dbConn, err := gorm.Open(postgres.Open(dsn))
//
// 	err = app.Migrate(dbConn)
// 	require.NoError(t, err)
//
// 	jobsService := services.NewJobsServiceImpl(repos.NewJobsRepoImpl(dbConn))
// 	agentsRepo := repos.NewAgentsRepoImpl(dbConn)
//
// 	queueService := services.NewQueueServiceImpl(jobsService, repos.NewNetworkNodesRepoImpl(dbConn), agentsRepo)
//
// 	// t.Run("agent creation test", func(t *testing.T) {
// 	// 	agentsService := services.NewAgentsServiceImpl(agentsRepo)
// 	//
// 	// 	inet := pgtype.Inet{}
// 	// 	err = inet.Set("0.0.0.0")
// 	// 	require.NoError(t, err)
// 	//
// 	// 	agent := agentEntities.ScanAgent{
// 	// 		Name:        "Test Agent",
// 	// 		IPAddress:   inet,
// 	// 		Host:        "0.0.0.0:2814",
// 	// 		IsActive:    true,
// 	// 		IsHomeBound: false,
// 	// 		Description: "test agent",
// 	// 		MinPriority: jobEntities.JOB_PRIORITY_LOW,
// 	// 		IsPrivate:   false,
// 	// 	}
// 	//
// 	// 	agent, err = agentsService.SaveAgent(agent)
// 	//
// 	// 	require.NoError(t, err)
// 	// 	require.NotNil(t, agent.UUID)
// 	// })
//
// 	t.Run("test agent connection checks", func(t *testing.T) {
// 		dialerUUIDs := queueService.RetrieveConnectedAgentsUUIDs()
//
// 		require.Len(t, dialerUUIDs, 1)
// 	})
//
// 	t.Run("test agent jobs empty", func(t *testing.T) {
// 		jobs := queueService.RetrieveAllJobs()
//
// 		require.Len(t, jobs, 2)
// 		require.Len(t, jobs[0], 0)
// 		require.Len(t, jobs[1], 0)
// 	})
//
// 	t.Run("test agent job execution", func(t *testing.T) {
// 		uuid, err := queueService.QueueNewJob(jobEntities.JobCreateParams{
// 			Type:     jobEntities.JOB_TYPE_OSS,
// 			Priority: jobEntities.JOB_PRIORITY_HIGH,
// 			Weight:   10,
// 			Targets:  []string{"ya.ru"},
// 			OpenSourceProviders: []jobEntities.SupportedOSSProvider{
// 				jobEntities.OSS_PROVIDER_VIRUS_TOTAL,
// 			},
// 			Delay:   1000,
// 			Timout:  5000,
// 			Retries: 2,
// 		})
//
// 		require.NoError(t, err)
// 		require.NotNil(t, uuid)
//
// 		jobs := queueService.RetrieveAllJobs()
//
// 		require.Len(t, jobs, 2)
// 		require.Len(t, jobs[0], 0)
// 		require.Len(t, jobs[1], 1) // job is placed into queue
// 	})
// }
