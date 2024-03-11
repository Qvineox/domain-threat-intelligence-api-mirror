package routing

import (
	"domain_threat_intelligence_api/api/rest/auth"
	apiErrors "domain_threat_intelligence_api/api/rest/error"
	"domain_threat_intelligence_api/api/rest/success"
	"domain_threat_intelligence_api/cmd/core"
	"domain_threat_intelligence_api/cmd/core/entities/blacklistEntities"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgtype"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"time"
)

type BlacklistsRouter struct {
	service core.IBlacklistsService
	path    *gin.RouterGroup

	cachedValues struct {
		stats BlacklistedStatistics
	}
}

type BlacklistedStatistics struct {
	LastEval     *time.Time `json:"LastEval"`
	TotalURLs    int64      `json:"TotalURLs"`
	TotalDomains int64      `json:"TotalDomains"`
	TotalEmails  int64      `json:"TotalEmails"`
	TotalIPs     int64      `json:"TotalIPs"`

	CreatedByDate    HostsByDate `json:"CreatedByDate"`
	DiscoveredByDate HostsByDate `json:"DiscoveredByDate"`
}

type HostsByDate struct {
	Dates []string `json:"Dates"`

	IPs     []uint64 `json:"IPs"`
	Domains []uint64 `json:"Domains"`
	URLs    []uint64 `json:"URLs"`
	Emails  []uint64 `json:"Emails"`
}

func NewBlacklistsRouter(service core.IBlacklistsService, path *gin.RouterGroup, auth *auth.MiddlewareService) *BlacklistsRouter {
	router := BlacklistsRouter{service: service, path: path}

	blacklistsGroup := path.Group("/blacklists")
	blacklistsGroup.Use(auth.RequireAuth())

	blacklistsWriteGroup := blacklistsGroup.Group("")
	blacklistsWriteGroup.Use(auth.RequireRole(4002))

	{
		blacklistsGroup.GET("/ip", router.GetBlackListedIPsByFilter)
		blacklistsWriteGroup.PUT("/ip", router.PutBlackListedIPs)
		blacklistsWriteGroup.DELETE("/ip", router.DeleteBlackListedIP)
	}

	{
		blacklistsGroup.GET("/domain", router.GetBlackListedDomainsByFilter)
		blacklistsWriteGroup.PUT("/domain", router.PutBlackListedDomains)
		blacklistsWriteGroup.DELETE("/domain", router.DeleteBlackListedDomain)
	}

	{
		blacklistsGroup.GET("/url", router.GetBlackListedURLsByFilter)
		blacklistsWriteGroup.PUT("/url", router.PutBlackListedURLs)
		blacklistsWriteGroup.DELETE("/url", router.DeleteBlackListedURL)
	}

	{
		blacklistsGroup.GET("/email", router.GetBlackListedEmailsByFilter)
		blacklistsWriteGroup.PUT("/email", router.PutBlackListedEmails)
		blacklistsWriteGroup.DELETE("/email", router.DeleteBlackListedEmail)
	}

	blacklistsGroup.GET("/host", router.GetBlackListedHostsByFilter)

	blacklistImportGroup := blacklistsGroup.Group("/import")
	blacklistImportGroup.Use(auth.RequireRole(4003))

	blacklistsImportWriteGroup := blacklistImportGroup.Group("")
	blacklistsImportWriteGroup.Use(auth.RequireRole(4002))

	{
		blacklistImportGroup.POST("/csv", router.PostImportBlacklistsFromCSVFile)
		blacklistImportGroup.POST("/stix", router.PostImportBlacklistsFromSTIXFile)
		blacklistImportGroup.GET("/event", router.GetImportEventByFilter)
		blacklistImportGroup.GET("/event/:event_id", router.GetImportEvent)
		blacklistsImportWriteGroup.DELETE("/event", router.DeleteImportEvent)
	}

	blacklistExportGroup := blacklistsGroup.Group("/export")
	blacklistExportGroup.Use(auth.RequireRole(4004))

	{
		blacklistExportGroup.POST("/csv", router.PostExportBlacklistsToCSV)
		blacklistExportGroup.POST("/json", router.PostExportBlacklistsToJSON)
		blacklistExportGroup.POST("/naumen", router.PostExportBlacklistsToNaumen)
	}

	blacklistsGroup.GET("/sources", router.GetBlackListSources).Use(auth.RequireRole(4001))
	blacklistsGroup.GET("/stats", router.GetStatistics)

	router.recountStatistics()

	return &router
}

// GetBlackListedHostsByFilter returns list of blacklisted hosts (all types) by filter
//
// @Summary            All hosts by filter
// @Description        Returns list of blacklisted hosts (all types) by filter
// @Tags               Blacklists
// @Security           ApiKeyAuth
// @Router             /blacklists/host [get]
// @ProduceAccessToken json
// @Param              source_id[]           query          []uint64 false "Source type IDs" collectionFormat(multi)
// @Param              import_event_id query       uint64            false "Import event ID"
// @Param              is_active             query          bool           false "Is active"
// @Param              created_after   query       string            false "Created timestamp is after"
// @Param              created_before  query       string            false "Created timestamp is before"
// @Param              search_string   query       string            false "value to search"
// @Param              limit                       query             int     true  "Query limit"
// @Param              offset                      query             int     false "Query offset"
// @Success            200                                  {object} []blacklistEntities.BlacklistedHost
// @Failure            401,400                     {object} apiErrors.APIError
func (r *BlacklistsRouter) GetBlackListedHostsByFilter(c *gin.Context) {
	params := blacklistEntities.BlacklistSearchFilter{}

	err := c.ShouldBindQuery(&params)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	if params.CreatedBefore != nil && !params.CreatedBefore.IsZero() {
		var d = params.CreatedBefore.Add((24*60 - 1) * time.Minute) // set to end of the day
		params.CreatedBefore = &d
	}

	if params.DiscoveredBefore != nil && !params.DiscoveredBefore.IsZero() {
		var d = params.DiscoveredBefore.Add((24*60 - 1) * time.Minute) // set to end of the day
		params.DiscoveredBefore = &d
	}

	hosts, err := r.service.RetrieveHostsByFilter(params)
	if err != nil {
		apiErrors.DatabaseErrorResponse(c, err)
		return
	}

	c.JSON(http.StatusOK, hosts)
}

// GetBlackListedIPsByFilter returns list of blacklisted IPs by filter
//
// @Summary            Blacklisted IPs by filter
// @Description        Returns list of blacklisted IPs by filter
// @Tags               Blacklists
// @Security           ApiKeyAuth
// @Router             /blacklists/ip [get]
// @ProduceAccessToken json
// @Param              source_id             query          []uint64 false "Source type IDs" collectionFormat(multi)
// @Param              import_event_id query       uint64            false "Import event ID"
// @Param              is_active             query          bool           false "Is active"
// @Param              created_after   query       string            false "Created timestamp is after"
// @Param              created_before  query       string            false "Created timestamp is before"
// @Param              search_string   query       string            false "CIDR to search (must include IP/MASK)"
// @Param              limit                       query             int     true  "Query limit"
// @Param              offset                      query             int     false "Query offset"
// @Success            200                                  {object} []blacklistEntities.BlacklistedIP
// @Failure            401,400                     {object} apiErrors.APIError
func (r *BlacklistsRouter) GetBlackListedIPsByFilter(c *gin.Context) {
	params := blacklistEntities.BlacklistSearchFilter{}

	err := c.ShouldBindQuery(&params)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	if params.CreatedBefore != nil && !params.CreatedBefore.IsZero() {
		var d = params.CreatedBefore.Add((24*60 - 1) * time.Minute) // set to end of the day
		params.CreatedBefore = &d
	}

	if params.DiscoveredBefore != nil && !params.DiscoveredBefore.IsZero() {
		var d = params.DiscoveredBefore.Add((24*60 - 1) * time.Minute) // set to end of the day
		params.DiscoveredBefore = &d
	}

	// check if search string is IP or IP with mask
	_, _, err = net.ParseCIDR(params.SearchString)
	if len(params.SearchString) > 0 && err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	ips, err := r.service.RetrieveIPsByFilter(params)
	if err != nil {
		apiErrors.DatabaseErrorResponse(c, err)
		return
	}

	c.JSON(http.StatusOK, ips)
}

// GetBlackListedDomainsByFilter returns list of blacklisted domains by filter
//
// @Summary            Blacklisted domains by filter
// @Description        Returns list of blacklisted domains by filter
// @Tags               Blacklists
// @Security           ApiKeyAuth
// @Router             /blacklists/domain [get]
// @ProduceAccessToken json
// @Param              source_id             query          []uint64 false "Source type IDs" collectionFormat(multi)
// @Param              import_event_id query       uint64            false "Import event ID"
// @Param              is_active             query          bool           false "Is active"
// @Param              created_after   query       string            false "Created timestamp is after"
// @Param              created_before  query       string            false "Created timestamp is before"
// @Param              search_string   query       string            false "Substring to search"
// @Param              limit                       query             int     true  "Query limit"
// @Param              offset                      query             int     false "Query offset"
// @Success            200                                  {object} []blacklistEntities.BlacklistedDomain
// @Failure            401,400                     {object} apiErrors.APIError
func (r *BlacklistsRouter) GetBlackListedDomainsByFilter(c *gin.Context) {
	params := blacklistEntities.BlacklistSearchFilter{}

	err := c.ShouldBindQuery(&params)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	if params.CreatedBefore != nil && !params.CreatedBefore.IsZero() {
		var d = params.CreatedBefore.Add((24*60 - 1) * time.Minute) // set to end of the day
		params.CreatedBefore = &d
	}

	if params.DiscoveredBefore != nil && !params.DiscoveredBefore.IsZero() {
		var d = params.DiscoveredBefore.Add((24*60 - 1) * time.Minute) // set to end of the day
		params.DiscoveredBefore = &d
	}

	domains, err := r.service.RetrieveDomainsByFilter(params)
	if err != nil {
		apiErrors.DatabaseErrorResponse(c, err)
		return
	}

	c.JSON(http.StatusOK, domains)
}

// GetBlackListedURLsByFilter returns list of blacklisted URLs by filter
//
// @Summary            Blacklisted URLs by filter
// @Description        Returns list of blacklisted URLs by filter
// @Tags               Blacklists
// @Security           ApiKeyAuth
// @Router             /blacklists/url [get]
// @ProduceAccessToken json
// @Param              source_id             query          []uint64 false "Source type IDs" collectionFormat(multi)
// @Param              import_event_id query       uint64            false "Import event ID"
// @Param              is_active             query          bool           false "Is active"
// @Param              created_after   query       string            false "Created timestamp is after"
// @Param              created_before  query       string            false "Created timestamp is before"
// @Param              search_string   query       string            false "Substring to search"
// @Param              limit                       query             int     true  "Query limit"
// @Param              offset                      query             int     false "Query offset"
// @Success            200                                  {object} []blacklistEntities.BlacklistedURL
// @Failure            401,400                     {object} apiErrors.APIError
func (r *BlacklistsRouter) GetBlackListedURLsByFilter(c *gin.Context) {
	params := blacklistEntities.BlacklistSearchFilter{}

	err := c.ShouldBindQuery(&params)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	if params.CreatedBefore != nil && !params.CreatedBefore.IsZero() {
		var d = params.CreatedBefore.Add((24*60 - 1) * time.Minute) // set to end of the day
		params.CreatedBefore = &d
	}

	if params.DiscoveredBefore != nil && !params.DiscoveredBefore.IsZero() {
		var d = params.DiscoveredBefore.Add((24*60 - 1) * time.Minute) // set to end of the day
		params.DiscoveredBefore = &d
	}

	urls, err := r.service.RetrieveURLsByFilter(params)
	if err != nil {
		apiErrors.DatabaseErrorResponse(c, err)
		return
	}

	c.JSON(http.StatusOK, urls)
}

// GetBlackListedEmailsByFilter returns list of blacklisted emails by filter
//
// @Summary            Blacklisted emails by filter
// @Description        Returns list of blacklisted emails by filter
// @Tags               Blacklists
// @Security           ApiKeyAuth
// @Router             /blacklists/email [get]
// @ProduceAccessToken json
// @Param              source_id             query          []uint64 false "Source type IDs" collectionFormat(multi)
// @Param              import_event_id query       uint64            false "Import event ID"
// @Param              is_active             query          bool           false "Is active"
// @Param              created_after   query       string            false "Created timestamp is after"
// @Param              created_before  query       string            false "Created timestamp is before"
// @Param              search_string   query       string            false "Substring to search"
// @Param              limit                       query             int     true  "Query limit"
// @Param              offset                      query             int     false "Query offset"
// @Success            200                                  {object} []blacklistEntities.BlacklistedEmail
// @Failure            401,400                     {object} apiErrors.APIError
func (r *BlacklistsRouter) GetBlackListedEmailsByFilter(c *gin.Context) {
	params := blacklistEntities.BlacklistSearchFilter{}

	err := c.ShouldBindQuery(&params)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	if params.CreatedBefore != nil && !params.CreatedBefore.IsZero() {
		var d = params.CreatedBefore.Add((24*60 - 1) * time.Minute) // set to end of the day
		params.CreatedBefore = &d
	}

	if params.DiscoveredBefore != nil && !params.DiscoveredBefore.IsZero() {
		var d = params.DiscoveredBefore.Add((24*60 - 1) * time.Minute) // set to end of the day
		params.DiscoveredBefore = &d
	}

	urls, err := r.service.RetrieveEmailsByFilter(params)
	if err != nil {
		apiErrors.DatabaseErrorResponse(c, err)
		return
	}

	c.JSON(http.StatusOK, urls)
}

// PutBlackListedDomains accepts and saves list of blacklisted domains
//
// @Summary            Save blacklisted domains
// @Description        Accepts and saves list of blacklisted domains
// @Tags               Blacklists
// @Security           ApiKeyAuth
// @Router             /blacklists/domain [put]
// @ProduceAccessToken json
// @Param              hosts   body              blacklistInsertParams true "IPs to save"
// @Success            201              {object} success.DatabaseResponse
// @Failure            401,400 {object} apiErrors.APIError
func (r *BlacklistsRouter) PutBlackListedDomains(c *gin.Context) {
	var params blacklistInsertParams

	err := c.ShouldBindJSON(&params)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	var domains []blacklistEntities.BlacklistedDomain
	for _, h := range params.Hosts {
		domains = append(domains, blacklistEntities.BlacklistedDomain{
			URN:         h.Host,
			Description: h.Description,
			SourceID:    h.SourceID,
		})
	}

	rows, err := r.service.SaveDomains(domains)
	if err != nil {
		apiErrors.DatabaseErrorResponse(c, err)
		return
	}

	success.SavedResponse(c, rows)
}

// PutBlackListedIPs accepts and saves list of blacklisted IPs
//
// @Summary            Save blacklisted ips
// @Description        Accepts and saves list of blacklisted IPs
// @Tags               Blacklists
// @Security           ApiKeyAuth
// @Router             /blacklists/ip [put]
// @ProduceAccessToken json
// @Param              hosts   body              blacklistInsertParams true "IPs to save"
// @Success            201              {object} success.DatabaseResponse
// @Failure            401,400 {object} apiErrors.APIError
func (r *BlacklistsRouter) PutBlackListedIPs(c *gin.Context) {
	var params blacklistInsertParams

	err := c.ShouldBindJSON(&params)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	var ips []blacklistEntities.BlacklistedIP
	for _, h := range params.Hosts {
		var ipAddress = pgtype.Inet{}

		err = ipAddress.Set(h.Host)
		if err != nil {
			apiErrors.ParamsErrorResponse(c, err)
			return
		}

		ips = append(ips, blacklistEntities.BlacklistedIP{
			IPAddress:   ipAddress,
			Description: h.Description,
			SourceID:    h.SourceID,
		})
	}

	rows, err := r.service.SaveIPs(ips)
	if err != nil {
		apiErrors.DatabaseErrorResponse(c, err)
		return
	}

	success.SavedResponse(c, rows)
}

// PutBlackListedURLs accepts and saves list of blacklisted URLs
//
// @Summary            Save blacklisted URLs
// @Description        Accepts and saves list of blacklisted URLs
// @Tags               Blacklists
// @Security           ApiKeyAuth
// @Router             /blacklists/url [put]
// @ProduceAccessToken json
// @Param              hosts   body              blacklistInsertParams true "URLs to save"
// @Success            201              {object} success.DatabaseResponse
// @Failure            401,400 {object} apiErrors.APIError
func (r *BlacklistsRouter) PutBlackListedURLs(c *gin.Context) {
	var params blacklistInsertParams

	err := c.ShouldBindJSON(&params)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	var urls []blacklistEntities.BlacklistedURL
	for _, h := range params.Hosts {
		urls = append(urls, blacklistEntities.BlacklistedURL{
			URL:         h.Host,
			Description: h.Description,
			SourceID:    h.SourceID,
		})
	}

	rows, err := r.service.SaveURLs(urls)
	if err != nil {
		apiErrors.DatabaseErrorResponse(c, err)
		return
	}

	success.SavedResponse(c, rows)
}

// PutBlackListedEmails accepts and saves list of blacklisted emails
//
// @Summary            Save blacklisted emails
// @Description        Accepts and saves list of blacklisted emails
// @Tags               Blacklists
// @Security           ApiKeyAuth
// @Router             /blacklists/email [put]
// @ProduceAccessToken json
// @Param              hosts   body              blacklistInsertParams true "emails to save"
// @Success            201              {object} success.DatabaseResponse
// @Failure            401,400 {object} apiErrors.APIError
func (r *BlacklistsRouter) PutBlackListedEmails(c *gin.Context) {
	var params blacklistInsertParams

	err := c.ShouldBindJSON(&params)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	var emails []blacklistEntities.BlacklistedEmail
	for _, h := range params.Hosts {
		emails = append(emails, blacklistEntities.BlacklistedEmail{
			Email:       h.Host,
			Description: h.Description,
			SourceID:    h.SourceID,
		})
	}

	rows, err := r.service.SaveEmails(emails)
	if err != nil {
		apiErrors.DatabaseErrorResponse(c, err)
		return
	}

	success.SavedResponse(c, rows)
}

type blacklistInsertParams struct {
	Hosts []struct {
		Host        string `json:"host" binding:"required"`
		SourceID    uint64 `json:"source_id" binding:"required"`
		Description string `json:"description,omitempty"`
	} `json:"hosts" binding:"required,min=1,dive"` // issue: https://github.com/gin-gonic/gin/issues/3436
}

// DeleteBlackListedIP accepts and deletes single blacklisted IP
//
// @Summary            Delete blacklisted IP
// @Description        Accepts and deletes single blacklisted IP
// @Tags               Blacklists
// @Security           ApiKeyAuth
// @Router             /blacklists/ip [delete]
// @ProduceAccessToken json
// @Param              id               body      byUUIDParams true "record UUID to delete"
// @Success            200              {object} success.DatabaseResponse
// @Failure            401,400 {object} apiErrors.APIError
// @Failure            401              {object} apiErrors.APIError
func (r *BlacklistsRouter) DeleteBlackListedIP(c *gin.Context) {
	var params byUUIDParams

	err := c.ShouldBindJSON(&params)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	uuid := pgtype.UUID{}
	err = uuid.Set(params.UUID)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	rows, err := r.service.DeleteIP(uuid)
	if err != nil {
		apiErrors.DatabaseErrorResponse(c, err)
		return
	}

	success.DeletedResponse(c, rows)
}

// DeleteBlackListedDomain accepts and deletes single blacklisted domain
//
// @Summary            Delete blacklisted domain
// @Description        Accepts and deletes single blacklisted domain
// @Tags               Blacklists
// @Security           ApiKeyAuth
// @Router             /blacklists/domain [delete]
// @ProduceAccessToken json
// @Param              id               body      byUUIDParams true "record UUID to delete"
// @Success            200              {object} success.DatabaseResponse
// @Failure            401,400 {object} apiErrors.APIError
// @Failure            401              {object} apiErrors.APIError
func (r *BlacklistsRouter) DeleteBlackListedDomain(c *gin.Context) {
	var params byUUIDParams

	err := c.ShouldBindJSON(&params)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	uuid := pgtype.UUID{}
	err = uuid.Set(params.UUID)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	rows, err := r.service.DeleteDomain(uuid)
	if err != nil {
		apiErrors.DatabaseErrorResponse(c, err)
		return
	}

	success.DeletedResponse(c, rows)
}

// DeleteBlackListedURL accepts and deletes single blacklisted URL
//
// @Summary            Delete blacklisted URL
// @Description        Accepts and deletes single blacklisted URL
// @Tags               Blacklists
// @Security           ApiKeyAuth
// @Router             /blacklists/url [delete]
// @ProduceAccessToken json
// @Param              id               body      byUUIDParams true "record UUID to delete"
// @Success            200              {object} success.DatabaseResponse
// @Failure            401,400 {object} apiErrors.APIError
// @Failure            401              {object} apiErrors.APIError
func (r *BlacklistsRouter) DeleteBlackListedURL(c *gin.Context) {
	var params byUUIDParams

	err := c.ShouldBindJSON(&params)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	uuid := pgtype.UUID{}
	err = uuid.Set(params.UUID)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	rows, err := r.service.DeleteURL(uuid)
	if err != nil {
		apiErrors.DatabaseErrorResponse(c, err)
		return
	}

	success.DeletedResponse(c, rows)
}

// DeleteBlackListedEmail accepts and deletes single blacklisted email
//
// @Summary            Delete blacklisted email
// @Description        Accepts and deletes single blacklisted email
// @Tags               Blacklists
// @Security           ApiKeyAuth
// @Router             /blacklists/email [delete]
// @ProduceAccessToken json
// @Param              id               body      byUUIDParams true "record UUID to delete"
// @Success            200              {object} success.DatabaseResponse
// @Failure            401,400 {object} apiErrors.APIError
// @Failure            401              {object} apiErrors.APIError
func (r *BlacklistsRouter) DeleteBlackListedEmail(c *gin.Context) {
	var params byUUIDParams

	err := c.ShouldBindJSON(&params)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	uuid := pgtype.UUID{}
	err = uuid.Set(params.UUID)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	rows, err := r.service.DeleteEmail(uuid)
	if err != nil {
		apiErrors.DatabaseErrorResponse(c, err)
		return
	}

	success.DeletedResponse(c, rows)
}

type byUUIDParams struct {
	UUID string `json:"UUID" binding:"uuid4,required"`
}

type byIDParams struct {
	ID uint64 `json:"ID" binding:"required"`
}

// PostImportBlacklistsFromCSVFile accepts and imports blacklisted hosts from CSV file
//
// @Summary            Import blacklisted hosts from CSV file
// @Description        Accepts and imports blacklisted hosts from CSV file
// @Tags               Blacklists, Import
// @Security           ApiKeyAuth
// @Router             /blacklists/import/csv [post]
// @ProduceAccessToken json
// @Param              file_upload            formData file     true "file to import"
// @Param              discovered_at formData string   true     "discovery date"
// @Param              extract_all            formData string   true     "other types extraction"
// @Success            201                                      {object} blacklistEntities.BlacklistImportEvent
// @Failure            401,400                         {object} apiErrors.APIError
func (r *BlacklistsRouter) PostImportBlacklistsFromCSVFile(c *gin.Context) {
	form, err := c.MultipartForm()
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	files := form.File["file_upload"]

	var discoveredAt time.Time
	if len(form.Value["discovered_at"]) == 1 {
		discoveredAt, err = time.Parse("2006-01-02", form.Value["discovered_at"][0])
		if err != nil {
			apiErrors.ParamsErrorResponse(c, err)
			return
		}
	} else {
		discoveredAt = time.Now()
	}

	extractAll := false
	e := form.Value["extract_all"]
	if len(e) == 1 && e[0] == "true" {
		extractAll = true
	}

	if len(files) == 0 {
		apiErrors.ParamsErrorResponse(c, errors.New("files not provided"))
		return
	}

	var event blacklistEntities.BlacklistImportEvent

	for _, f := range files {
		switch filepath.Ext(f.Filename) {
		case ".csv":
			openedFile, err := f.Open()
			if err != nil {
				apiErrors.FileDecodingErrorResponse(c, err)
				return
			}

			csvReader := csv.NewReader(openedFile)
			data, err := csvReader.ReadAll()
			if err != nil {
				apiErrors.FileReadingErrorResponse(c, err)
				return
			}

			event, err = r.service.ImportFromCSV(data, discoveredAt, extractAll)
			if err != nil {
				apiErrors.FileProcessingErrorResponse(c, err)
			}
		default:
			apiErrors.FileExtensionNotSupportedErrorResponse(c, errors.New("file extension not supported"))
			return
		}
	}

	go r.recountStatistics()

	c.JSON(http.StatusCreated, event)
}

// PostImportBlacklistsFromSTIXFile accepts and imports blacklisted hosts from STIX 2.0 file
//
// @Summary            Import blacklisted hosts from file (STIX 2.0)
// @Description        Accepts and imports blacklisted hosts from STIX 2.0 file
// @Tags               Blacklists, Import
// @Security           ApiKeyAuth
// @Router             /blacklists/import/stix [post]
// @Accept             mpfd
// @ProduceAccessToken json
// @Param              file_upload formData file     true     "files to import"
// @Param              extract_all formData string   true     "other types extraction"
// @Success            201                           {object} blacklistEntities.BlacklistImportEvent
// @Failure            401,400              {object} apiErrors.APIError
func (r *BlacklistsRouter) PostImportBlacklistsFromSTIXFile(c *gin.Context) {
	form, err := c.MultipartForm()
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	files := form.File["file_upload"]
	if len(files) == 0 {
		apiErrors.ParamsErrorResponse(c, errors.New("files not provided"))
		return
	}

	extractAll := false
	e := form.Value["extract_all"]
	if len(e) == 1 && e[0] == "true" {
		extractAll = true
	}

	var bundles []blacklistEntities.STIX2Bundle

	for _, f := range files {
		var bundle blacklistEntities.STIX2Bundle

		openedFile, err := f.Open()
		if err != nil {
			apiErrors.FileDecodingErrorResponse(c, err)
			return
		}

		file, err := io.ReadAll(openedFile)
		if err != nil {
			apiErrors.FileReadingErrorResponse(c, err)
			return
		}

		switch filepath.Ext(f.Filename) {
		case ".json":
			err = json.Unmarshal(file, &bundle)
			if err != nil {
				apiErrors.FileDecodingErrorResponse(c, err)
				return
			}

			if len(bundle.ID) == 0 {
				apiErrors.FileDecodingErrorResponse(c, errors.New("bundles not found"))
				return
			}

			bundles = append(bundles, bundle)
		default:
			apiErrors.FileExtensionNotSupportedErrorResponse(c, errors.New("file extension not supported"))
			return
		}
	}

	event, err := r.service.ImportFromSTIX2(bundles, extractAll)
	if err != nil {
		apiErrors.FileProcessingErrorResponse(c, err)
		return
	}

	go r.recountStatistics()

	c.JSON(http.StatusCreated, event)
}

// GetImportEvent returns import event data with all included blacklisted hosts
//
// @Summary            Get import event
// @Description        Returns import event data with all included blacklisted hosts
// @Tags               Blacklists, Import
// @Security           ApiKeyAuth
// @Router             /blacklists/import/event/{event_id} [get]
// @ProduceAccessToken json
// @Param              event_id path          int      true "Event ID"
// @Success            200                    {object} blacklistEntities.BlacklistImportEvent
// @Failure            401,400       {object} apiErrors.APIError
func (r *BlacklistsRouter) GetImportEvent(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("event_id"), 10, 64)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	event, err := r.service.RetrieveImportEvent(id)
	if err != nil {
		apiErrors.DatabaseErrorResponse(c, err)
		return
	} else if event.ID == 0 {
		apiErrors.DatabaseEntityNotFound(c)
		return
	}

	c.JSON(http.StatusOK, event)
}

// GetImportEventByFilter returns import events without data
//
// @Summary            Get import events list
// @Description        Returns import events without data
// @Tags               Blacklists, Import
// @Security           ApiKeyAuth
// @Router             /blacklists/import/event [get]
// @ProduceAccessToken json
// @Param              created_after  query  string   false    "Created timestamp is after"
// @Param              created_before query  string   false    "Created timestamp is before"
// @Param              type                  query             string false "Type to search"
// @Param              limit                 query             int          true  "Query limit"
// @Param              offset                query             int          false "Query offset"
// @Success            200                            {object} []blacklistEntities.BlacklistImportEvent
// @Failure            401,400               {object} apiErrors.APIError
func (r *BlacklistsRouter) GetImportEventByFilter(c *gin.Context) {
	var params blacklistEntities.BlacklistImportEventFilter

	err := c.ShouldBindQuery(&params)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	if params.CreatedBefore != nil && !params.CreatedBefore.IsZero() {
		var d = params.CreatedBefore.Add((24*60 - 1) * time.Minute) // set to end of the day
		params.CreatedBefore = &d
	}

	events, err := r.service.RetrieveImportEventsByFilter(params)
	if err != nil {
		apiErrors.DatabaseErrorResponse(c, err)
		return
	}

	c.JSON(http.StatusOK, events)
}

// DeleteImportEvent accepts and deletes single blacklist import event
//
// @Summary            Delete blacklist import event
// @Description        Accepts and deletes single blacklist import event
// @Tags               Blacklists, Import
// @Security           ApiKeyAuth
// @Router             /blacklists/import/event [delete]
// @ProduceAccessToken json
// @Param              id               body      byIDParams true "record ID to delete"
// @Success            200              {object} success.DatabaseResponse
// @Failure            401,400 {object} apiErrors.APIError
// @Failure            401              {object} apiErrors.APIError
func (r *BlacklistsRouter) DeleteImportEvent(c *gin.Context) {
	var params byIDParams

	err := c.ShouldBindJSON(&params)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	rows, err := r.service.DeleteImportEvent(params.ID)
	if err != nil {
		return
	}

	success.DeletedResponse(c, rows)
}

// PostExportBlacklistsToCSV accepts filters and returns exported blacklisted hosts in CSV
//
// @Summary            Exports blacklisted hosts into CSV
// @Description        Accepts filters and returns exported blacklisted hosts in CSV
// @Tags               Blacklists, Export
// @Security           ApiKeyAuth
// @Router             /blacklists/export/csv [post]
// @ProduceAccessToken json
// @Param              source_id[]                    query  []uint64 false "Source type IDs" collectionFormat(multi)
// @Param              created_after           query  string          false "Created timestamp is after"
// @Param              created_before          query  string          false "Created timestamp is before"
// @Param              discovered_after  query string        false    "Discovery timestamp is after"
// @Param              discovered_before query string        false    "Discovery timestamp is before"
// @ProduceAccessToken application/csv
// @Success            200              {file}  file
// @Failure            401,400 {object} apiErrors.APIError
func (r *BlacklistsRouter) PostExportBlacklistsToCSV(c *gin.Context) {
	params := blacklistEntities.BlacklistSearchFilter{}

	err := c.ShouldBindQuery(&params)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	if params.CreatedBefore != nil && !params.CreatedBefore.IsZero() {
		var d = params.CreatedBefore.Add((24*60 - 1) * time.Minute) // set to end of the day
		params.CreatedBefore = &d
	}

	if params.DiscoveredBefore != nil && !params.DiscoveredBefore.IsZero() {
		var d = params.DiscoveredBefore.Add((24*60 - 1) * time.Minute) // set to end of the day
		params.DiscoveredBefore = &d
	}

	params.Limit = 0
	params.Offset = 0

	jsonBytes, err := r.service.ExportToCSV(params)
	if err != nil {
		apiErrors.FileProcessingErrorResponse(c, err)
		return
	}

	pattern := fmt.Sprintf("export_%d.*.csv", time.Now().Unix())
	file, err := os.CreateTemp("", pattern)
	if err != nil {
		apiErrors.FileProcessingErrorResponse(c, err)
		return
	}
	defer os.Remove(file.Name())

	_, err = file.Write(jsonBytes)
	if err != nil {
		apiErrors.FileProcessingErrorResponse(c, err)
		return
	}

	c.FileAttachment(file.Name(), filepath.Base(file.Name()))
}

// PostExportBlacklistsToJSON accepts filters and returns exported blacklisted hosts in JSON. ref: https://github.com/swaggo/swag/issues/726
//
// @Summary            Exports blacklisted hosts into JSON
// @Description        Accepts filters and returns exported blacklisted hosts in JSON
// @Tags               Blacklists, Export
// @Security           ApiKeyAuth
// @Router             /blacklists/export/json [post]
// @ProduceAccessToken json
// @Param              source_id[]                    query  []uint64 false "Source type IDs" collectionFormat(multi)
// @Param              created_after           query  string          false "Created timestamp is after"
// @Param              created_before          query  string          false "Created timestamp is before"
// @Param              discovered_after  query string        false    "Discovery timestamp is after"
// @Param              discovered_before query string        false    "Discovery timestamp is before"
// @ProduceAccessToken application/json
// @Success            200              {file}  file
// @Failure            401,400 {object} apiErrors.APIError
// @Failure            401              {object} apiErrors.APIError
func (r *BlacklistsRouter) PostExportBlacklistsToJSON(c *gin.Context) {
	params := blacklistEntities.BlacklistSearchFilter{}

	err := c.ShouldBindQuery(&params)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	// reset all params if exporting by event id
	if params.CreatedBefore != nil && !params.CreatedBefore.IsZero() {
		var d = params.CreatedBefore.Add((24*60 - 1) * time.Minute) // set to end of the day
		params.CreatedBefore = &d
	}

	if params.DiscoveredBefore != nil && !params.DiscoveredBefore.IsZero() {
		var d = params.DiscoveredBefore.Add((24*60 - 1) * time.Minute) // set to end of the day
		params.DiscoveredBefore = &d
	}

	params.Limit = 0
	params.Offset = 0

	jsonBytes, err := r.service.ExportToJSON(params)
	if err != nil {
		apiErrors.FileProcessingErrorResponse(c, err)
		return
	}

	pattern := fmt.Sprintf("export_%d.*.json", time.Now().Unix())
	file, err := os.CreateTemp("", pattern)
	if err != nil {
		apiErrors.FileProcessingErrorResponse(c, err)
		return
	}
	defer os.Remove(file.Name())

	_, err = file.Write(jsonBytes)
	if err != nil {
		apiErrors.FileProcessingErrorResponse(c, err)
		return
	}

	c.FileAttachment(file.Name(), filepath.Base(file.Name()))
}

// PostExportBlacklistsToNaumen sends service call to Naumen Service Desk with hosts selected to block by filter
//
// @Summary            Send hosts to Naumen Service Desk
// @Description        Sends service call to Naumen Service Desk with hosts selected to block by filter
// @Tags               Blacklists, Export
// @Security           ApiKeyAuth
// @Router             /blacklists/export/naumen [post]
// @ProduceAccessToken json
// @Param              source_id             query          []uint64 false "Source type IDs" collectionFormat(multi)
// @Param              import_event_id query       uint64            false "Import event ID"
// @Param              is_active             query          bool           false "Is active"
// @Param              created_after   query       string            false "Created timestamp is after"
// @Param              created_before  query       string            false "Created timestamp is before"
// @Param              search_string   query       string            false "Substring to search"
// @Success            201                                  {object} serviceDeskEntities.ServiceDeskTicket
// @Failure            401,400                     {object} apiErrors.APIError
func (r *BlacklistsRouter) PostExportBlacklistsToNaumen(c *gin.Context) {
	params := blacklistEntities.BlacklistSearchFilter{}

	err := c.ShouldBindQuery(&params)
	if err != nil {
		apiErrors.ParamsErrorResponse(c, err)
		return
	}

	// reset all params if exporting by event id
	if params.CreatedBefore != nil && !params.CreatedBefore.IsZero() {
		var d = params.CreatedBefore.Add((24*60 - 1) * time.Minute) // set to end of the day
		params.CreatedBefore = &d
	}

	if params.DiscoveredBefore != nil && !params.DiscoveredBefore.IsZero() {
		var d = params.DiscoveredBefore.Add((24*60 - 1) * time.Minute) // set to end of the day
		params.DiscoveredBefore = &d
	}

	params.Limit = 0
	params.Offset = 0

	// remove limits if event defined
	if params.ImportEventID != 0 {
		params.Limit = 0
	}

	ticket, err := r.service.ExportToNaumen(params)
	if err != nil {
		apiErrors.InternalErrorResponse(c, err)
		return
	}

	c.JSON(http.StatusCreated, ticket)
}

// GetStatistics returns data containing overall amount of blacklisted entities
//
// @Summary            Returns amount of blacklisted entities
// @Description        Returns data containing overall amount of blacklisted entities
// @Tags               Blacklists
// @Security           ApiKeyAuth
// @Router             /blacklists/stats [get]
// @ProduceAccessToken json
// @ProduceAccessToken application/json
// @Success            200              {object} BlacklistedStatistics
// @Failure            401,400 {object} apiErrors.APIError
func (r *BlacklistsRouter) GetStatistics(c *gin.Context) {
	if r.cachedValues.stats.LastEval == nil || r.cachedValues.stats.LastEval.Before(time.Now().Add(-2*time.Hour)) {
		r.recountStatistics()
	}

	c.JSON(http.StatusOK, r.cachedValues.stats)
}

// GetBlackListSources returns all blacklist source types
//
// @Summary            Get blacklist sources
// @Description        Returns all available blacklist data sources
// @Tags               Blacklists
// @Security           ApiKeyAuth
// @Router             /blacklists/sources [get]
// @ProduceAccessToken json
// @ProduceAccessToken application/json
// @Success            200              {object} []blacklistEntities.BlacklistSource
// @Failure            401,400 {object} apiErrors.APIError
func (r *BlacklistsRouter) GetBlackListSources(c *gin.Context) {
	sources, err := r.service.RetrieveAllSources()
	if err != nil {
		apiErrors.DatabaseErrorResponse(c, err)
		return
	}

	c.JSON(http.StatusOK, sources)
}

func (r *BlacklistsRouter) recountStatistics() {
	now := time.Now()
	r.cachedValues.stats.LastEval = &now

	r.cachedValues.stats.TotalIPs, r.cachedValues.stats.TotalURLs, r.cachedValues.stats.TotalDomains, r.cachedValues.stats.TotalEmails = r.service.RetrieveTotalStatistics()

	// var byDate = make(map[string]*[3]uint64)

	statisticsByCreationDate, err := r.service.RetrieveByCreationDateStatistics(now.Add(-time.Hour*24*31*2), now)
	if err != nil {
		return
	}

	statisticsByDiscoveryDate, err := r.service.RetrieveByDiscoveryDateStatistics(now.Add(-time.Hour*24*31*2), now)
	if err != nil {
		return
	}

	var discovery = HostsByDate{
		Dates:   make([]string, 0),
		IPs:     make([]uint64, 0),
		Domains: make([]uint64, 0),
		URLs:    make([]uint64, 0),
		Emails:  make([]uint64, 0),
	}

	var creation = HostsByDate{
		Dates:   make([]string, 0),
		IPs:     make([]uint64, 0),
		Domains: make([]uint64, 0),
		URLs:    make([]uint64, 0),
		Emails:  make([]uint64, 0),
	}

	for _, v := range statisticsByCreationDate {
		date := v.Date.Format("02.01.2006")

		index := slices.Index(creation.Dates, date)
		if index == -1 {
			creation.Dates = append(creation.Dates, date)
			index = len(creation.Dates) - 1

			creation.URLs = append(creation.URLs, 0)
			creation.IPs = append(creation.IPs, 0)
			creation.Domains = append(creation.Domains, 0)
			creation.Emails = append(creation.Emails, 0)
		}

		switch v.Type {
		case "url":
			creation.URLs[index] = v.Count
		case "ip":
			creation.IPs[index] = v.Count
		case "domain":
			creation.Domains[index] = v.Count
		case "email":
			creation.Emails[index] = v.Count
		}
	}

	r.cachedValues.stats.CreatedByDate = creation

	for _, v := range statisticsByDiscoveryDate {
		date := v.Date.Format("02.01.2006")

		index := slices.Index(discovery.Dates, date)
		if index == -1 {
			discovery.Dates = append(discovery.Dates, date)
			index = len(discovery.Dates) - 1

			discovery.URLs = append(discovery.URLs, 0)
			discovery.IPs = append(discovery.IPs, 0)
			discovery.Domains = append(discovery.Domains, 0)
			discovery.Emails = append(discovery.Emails, 0)
		}

		switch v.Type {
		case "url":
			discovery.URLs[index] = v.Count
		case "ip":
			discovery.IPs[index] = v.Count
		case "domain":
			discovery.Domains[index] = v.Count
		case "email":
			discovery.Emails[index] = v.Count
		}
	}

	r.cachedValues.stats.DiscoveredByDate = discovery
}
