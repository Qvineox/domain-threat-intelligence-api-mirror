package routing

import (
	"domain_threat_intelligence_api/api/rest/auth"
	apiErrors "domain_threat_intelligence_api/api/rest/error"
	"domain_threat_intelligence_api/cmd/core"
	"domain_threat_intelligence_api/cmd/core/entities/jobEntities"
	"errors"
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
		queueModifyGroup.PATCH("/job", router.PatchQueuedJob)
	}

	queueDeleteGroup := queueGroup.Group("")
	queueDeleteGroup.Use(auth.RequireRole(5008))

	{
		queueDeleteGroup.DELETE("/job", router.DeleteQueuedJobByUUID)
	}

	return &router
}

// PostQueueJob accepts and adds new scanning job to queue
//
//	@Summary			Enqueue scanning job
//	@Description		Accepts and adds new scanning job to queue
//	@Tags				Queue
//	@Security			ApiKeyAuth
//	@Router				/scanning/queue/job [post]
//	@ProduceAccessToken	json
//	@Param				job		body		jobEntities.JobCreateParams	true	"New job to queue"
//	@Success			201		{object}	queuedJob
//	@Failure			401,400	{object}	apiErrors.APIError
func (r *QueueRouter) PostQueueJob(c *gin.Context) {
	var params = jobEntities.JobCreateParams{}

	err := c.ShouldBindJSON(&params)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	contextUserID, ok := c.Get("user_id")
	if !ok {
		apiErrors.ParamsErrorResponse(c, errors.New("missing user id"))
		return
	}

	id, ok := contextUserID.(uint64)
	if !ok {
		apiErrors.ParamsErrorResponse(c, errors.New("failed to obtain user id"))
		return
	}

	params.CreatedByUserID = &id

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

// DeleteQueuedJobByUUID accepts UUID and removed Job from scanning queue
//
//	@Summary			Delete single job from queue by UUID
//	@Description		Deletes single job from queue
//	@Tags				Queue
//	@Security			ApiKeyAuth
//	@Router				/scanning/queue/job [delete]
//	@ProduceAccessToken	json
//	@Param				id	body	removeFromQueueByUUIDParams	true	"job UUID to delete"
//	@Success			200
//	@Failure			404,401,400	{object}	apiErrors.APIError
func (r *QueueRouter) DeleteQueuedJobByUUID(c *gin.Context) {
	params := removeFromQueueByUUIDParams{}

	err := c.ShouldBindJSON(&params)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	uuid := &pgtype.UUID{}
	err = uuid.Set(params.UUID)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, errors.New("missing uuid"))
		return
	}

	err = r.service.CancelQueuedJob(uuid, params.Force)
	if err != nil {
		c.Status(http.StatusNotFound)
		return
	}

	c.Status(http.StatusOK)
}

type removeFromQueueByUUIDParams struct {
	UUID  string `json:"UUID" binding:"uuid4,required"`
	Force bool   `json:"Force"`
}

// GetQueuedJobs returns list of jobs from queue
//
//	@Summary			Enqueued scanning jobs
//	@Description		Returns list of jobs from queue
//	@Tags				Queue
//	@Security			ApiKeyAuth
//	@Router				/scanning/queue/jobs [get]
//	@ProduceAccessToken	json
//	@Success			200		{object}	[]jobEntities.Job
//	@Failure			401,400	{object}	apiErrors.APIError
func (r *QueueRouter) GetQueuedJobs(c *gin.Context) {
	jobs := r.service.RetrieveAllJobs()
	c.JSON(http.StatusOK, queuedJobs{
		Queued: jobs[0],
		Sent:   jobs[1],
		Latest: jobs[2],
	})
}

type queuedJobs struct {
	Queued []*jobEntities.Job `json:"queued"`
	Sent   []*jobEntities.Job `json:"sent"`
	Latest []*jobEntities.Job `json:"latest"`
}
