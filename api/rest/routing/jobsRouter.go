package routing

import (
	"domain_threat_intelligence_api/api/rest/auth"
	apiErrors "domain_threat_intelligence_api/api/rest/error"
	"domain_threat_intelligence_api/api/rest/success"
	"domain_threat_intelligence_api/cmd/core"
	"domain_threat_intelligence_api/cmd/core/entities/jobEntities"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgtype"
	"net/http"
	"time"
)

type JobsRouter struct {
	service        core.IJobsService
	path           *gin.RouterGroup
	authMiddleware *auth.MiddlewareService
}

func NewJobsRouter(service core.IJobsService, path *gin.RouterGroup, auth *auth.MiddlewareService) *JobsRouter {
	router := JobsRouter{service: service, path: path}

	jobsGroup := path.Group("/jobs")
	jobsGroup.Use(auth.RequireAuth())

	jobsViewGroup := jobsGroup.Group("")
	jobsViewGroup.Use(auth.RequireRole(5006))

	{
		jobsViewGroup.GET("/jobs", router.GetJobsByFilter)
		jobsViewGroup.GET("/job/:job_uuid", router.GetJobByUUID)
	}

	jobsModifyGroup := jobsGroup.Group("")
	jobsModifyGroup.Use(auth.RequireRole(5007))

	{
		jobsViewGroup.DELETE("/job", router.DeleteJobByUUID)
	}

	return &router
}

// GetJobsByFilter returns saved jobs by filter
//
// @Summary            Get jobs by filter
// @Description        Returns list of jobs by filter
// @Tags               Jobs
// @Security           ApiKeyAuth
// @Router             /jobs/jobs [get]
// @ProduceAccessToken json
// @Param              types[]                    query             []uint64 false "Job type IDs" collectionFormat(multi)
// @Param              status                     query             uint64         false          "Job status"
// @Param              priority             query          uint64            false "Job priority"
// @Param              created_by           query          uint64            false "Created by user with ID"
// @Param              is_finished          query          bool              false "Only finished jobs"
// @Param              created_after  query       string            false    "Created timestamp is after"
// @Param              created_before query       string            false    "Created timestamp is before"
// @Param              limit                      query             int        true  "Query limit"
// @Param              offset                     query             int        false "Query offset"
// @Success            200                                 {object} []jobEntities.Job
// @Failure            401,400                    {object} apiErrors.APIError
func (r *JobsRouter) GetJobsByFilter(c *gin.Context) {
	params := jobEntities.JobsSearchFilter{}

	err := c.ShouldBindQuery(&params)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	if params.CreatedBefore != nil && !params.CreatedBefore.IsZero() {
		var d = params.CreatedBefore.Add((24*60 - 1) * time.Minute) // set to end of the day
		params.CreatedBefore = &d
	}

	jobs, err := r.service.RetrieveJobsByFilter(params)
	if err != nil {
		apiErrors.DatabaseErrorResponse(c, err)
		return
	}

	c.JSON(http.StatusOK, jobs)
}

// GetJobByUUID accepts UUID and returns saved Job
//
// @Summary            Get single job by UUID
// @Description        Returns single job
// @Tags               Jobs
// @Security           ApiKeyAuth
// @Router             /jobs/job/{job_uuid} [get]
// @ProduceAccessToken json
// @Param              job_uuid    path      string   true "Job UUID"
// @Success            200                   {object} jobEntities.Job
// @Failure            404,401,400 {object} apiErrors.APIError
func (r *JobsRouter) GetJobByUUID(c *gin.Context) {
	uuidParam := c.Param("job_uuid")
	if len(uuidParam) == 0 {
		apiErrors.ParamsErrorResponse(c, errors.New("missing uuid"))
		return
	}

	uuid := pgtype.UUID{}
	err := uuid.Set(uuidParam)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, errors.New("missing uuid"))
		return
	}

	job, err := r.service.RetrieveJobByUUID(uuid)
	if err != nil {
		apiErrors.DatabaseErrorResponse(c, err)
		return
	} else if job.Meta == nil || job.Meta.UUID.Status == pgtype.Undefined {
		apiErrors.DatabaseEntityNotFound(c)
		return
	}

	c.JSON(http.StatusOK, job)
}

// DeleteJobByUUID accepts UUID and deletes Job
//
// @Summary            Delete single job by UUID
// @Description        Deletes single job
// @Tags               Jobs
// @Security           ApiKeyAuth
// @Router             /jobs/job [delete]
// @ProduceAccessToken json
// @Param              id               body      byUUIDParams true "record UUID to delete"
// @Success            200              {object} success.DatabaseResponse
// @Failure            401,400 {object} apiErrors.APIError
func (r *JobsRouter) DeleteJobByUUID(c *gin.Context) {
	params := byUUIDParams{}

	err := c.ShouldBindJSON(&params)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	uuid := pgtype.UUID{}
	err = uuid.Set(params.UUID)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, errors.New("missing uuid"))
		return
	}

	rows, err := r.service.DeleteJob(uuid)
	if err != nil {
		apiErrors.DatabaseErrorResponse(c, err)
		return
	}

	success.DeletedResponse(c, rows)
}
