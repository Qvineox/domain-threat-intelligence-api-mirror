package routing

import (
	"domain_threat_intelligence_api/api/rest/auth"
	apiErrors "domain_threat_intelligence_api/api/rest/error"
	"domain_threat_intelligence_api/cmd/core"
	"domain_threat_intelligence_api/cmd/core/entities/jobEntities"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgtype"
	"net/http"
)

type QueueRouter struct {
	service core.IQueueService
	path    *gin.RouterGroup
}

func NewQueueRouter(service core.IQueueService, path *gin.RouterGroup, auth *auth.MiddlewareService) *QueueRouter {
	router := QueueRouter{service: service, path: path}

	queueGroup := path.Group("/queue")
	queueGroup.Use(auth.RequireAuth())

	queueViewGroup := queueGroup.Group("")
	queueViewGroup.Use(auth.RequireRole(5006))

	{
		queueViewGroup.GET("/jobs", router.GetQueuedJobs)
	}

	queueExecuteGroup := queueGroup.Group("")
	queueExecuteGroup.Use(auth.RequireRole(5001))

	{
		queueExecuteGroup.POST("/job", router.PostQueueJob)
	}

	queueModifyGroup := queueGroup.Group("")
	queueModifyGroup.Use(auth.RequireRole(5007))

	{
		queueViewGroup.GET("/job", router.PatchQueuedJob)
	}

	queueDeleteGroup := queueGroup.Group("")
	queueDeleteGroup.Use(auth.RequireRole(5008))

	{
		queueViewGroup.DELETE("/job", router.DeleteQueuedJobByUUID)
	}

	return &router
}

// PostQueueJob accepts and adds new scanning job to queue
//
// @Summary            Enqueue scanning job
// @Description        Accepts and adds new scanning job to queue
// @Tags               Queue
// @Security           ApiKeyAuth
// @Router             /queue/job [post]
// @ProduceAccessToken json
// @Param              job     body     jobEntities.JobCreateParams true "New job to queue"
// @Success            201     {object} queuedJob
// @Failure            401,400 {object} apiErrors.APIError
func (r *QueueRouter) PostQueueJob(c *gin.Context) {
	var params = jobEntities.JobCreateParams{}

	err := c.ShouldBindJSON(&params)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	jobUUID, err := r.service.QueueNewJob(params)
	if err != nil {
		apiErrors.QueueErrorResponse(c, err)
		return
	}

	c.JSON(http.StatusCreated, queuedJob{UUID: jobUUID})
}

type queuedJob struct {
	UUID *pgtype.UUID `json:"UUID"`
}

func (r *QueueRouter) PatchQueuedJob(c *gin.Context) {

}

func (r *QueueRouter) DeleteQueuedJobByUUID(c *gin.Context) {

}

// GetQueuedJobs returns list of jobs from queue
//
// @Summary            Enqueued scanning jobs
// @Description        Returns list of jobs from queue
// @Tags               Queue
// @Security           ApiKeyAuth
// @Router             /queue/jobs [get]
// @ProduceAccessToken json
// @Success            200     {object} []jobEntities.Job
// @Failure            401,400 {object} apiErrors.APIError
func (r *QueueRouter) GetQueuedJobs(c *gin.Context) {
	jobs := r.service.RetrieveAllJobs()
	c.JSON(http.StatusOK, queuedJobs{
		Sent:   jobs[0],
		Queued: jobs[1],
	})
}

type queuedJobs struct {
	Queued []*jobEntities.Job `json:"queued"`
	Sent   []*jobEntities.Job `json:"sent"`
}
