package routing

import (
	"domain_threat_intelligence_api/api/rest/error"
	"domain_threat_intelligence_api/api/rest/success"
	"domain_threat_intelligence_api/cmd/core"
	"domain_threat_intelligence_api/cmd/core/entities"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgtype"
	"net"
	"net/http"
)

type BlacklistsRouter struct {
	service core.IBlacklistsService
	path    *gin.RouterGroup
}

func NewBlacklistsRouter(service core.IBlacklistsService, path *gin.RouterGroup) *BlacklistsRouter {
	router := BlacklistsRouter{service: service, path: path}

	blacklistsGroup := path.Group("/blacklists")

	{
		blacklistsGroup.GET("/ips", router.GetBlackListedIPsByFilter)
		blacklistsGroup.PUT("/ips", router.PutBlackListedIPs)
		blacklistsGroup.DELETE("/ip", router.DeleteBlackListedIP)
	}

	{
		blacklistsGroup.GET("/domains", router.GetBlackListedDomainsByFilter)
		blacklistsGroup.PUT("/domains", router.PutBlackListedDomains)
		blacklistsGroup.DELETE("/domain", router.DeleteBlackListedDomain)
	}

	blacklistImportGroup := blacklistsGroup.Group("/import")

	{
		blacklistImportGroup.POST("/fincert", router.PostImportBlacklistsFromFinCERTFile)
		blacklistImportGroup.POST("/stix", router.PostImportBlacklistsFromSTIXFile)
	}

	blacklistExportGroup := blacklistsGroup.Group("/export")

	{
		blacklistExportGroup.POST("/csv", router.PostExportBlacklistsToCSV)
		blacklistExportGroup.POST("/json", router.PostExportBlacklistsToJSON)
	}

	return &router
}

// GetBlackListedIPsByFilter returns list of blacklisted IPs by filter
//
// @Summary     blacklisted ips by filter
// @Description Gets list of blacklisted ips by filter
// @Tags        Blacklists
// @Router      /blacklists/ips [get]
// @Param       source_id      query    []uint64 false "Source type IDs" collectionFormat(multi)
// @Param       is_active      query    bool                     false "Is active"
// @Param       created_after  query    string                   false "Created timestamp is after"
// @Param       created_before query    string                   false "Created timestamp is before"
// @Param       search_string  query    string   false "CIDR to search (must include IP/MASK)"
// @Param       limit          query    int                      true  "Query limit"
// @Param       offset         query    int                      false "Query offset"
// @Success     200            {object} []entities.BlacklistedIP
// @Failure     400                     {object} error.APIError
func (r *BlacklistsRouter) GetBlackListedIPsByFilter(c *gin.Context) {
	params := entities.BlacklistFilter{}

	err := c.ShouldBindQuery(&params)
	if err != nil {
		error.ParamsErrorResponse(c, err)
		return
	}

	// check if search string is IP or IP with mask
	_, _, err = net.ParseCIDR(params.SearchString)
	if err != nil {
		error.ParamsErrorResponse(c, err)
		return
	}

	ips, err := r.service.RetrieveIPsByFilter(params)
	if err != nil {
		error.DatabaseErrorResponse(c, err)
		return
	}

	c.JSON(http.StatusOK, ips)
}

// GetBlackListedDomainsByFilter returns list of blacklisted domains by filter
//
// @Summary     blacklisted domains by filter
// @Description Gets list of blacklisted domains by filter
// @Tags        Blacklists
// @Router      /blacklists/domains [get]
// @Param       source_id      query    []uint64 false "Source type IDs" collectionFormat(multi)
// @Param       is_active      query    bool                     false "Is active"
// @Param       created_after  query    string                   false "Created timestamp is after"
// @Param       created_before query    string                   false "Created timestamp is before"
// @Param       search_string  query    string                   false "Substring to search"
// @Param       limit          query    int                      true  "Query limit"
// @Param       offset         query    int                      false "Query offset"
// @Success     200            {object} []entities.BlacklistedDomain
// @Failure     400         {object} error.APIError
func (r *BlacklistsRouter) GetBlackListedDomainsByFilter(c *gin.Context) {
	params := entities.BlacklistFilter{}

	err := c.ShouldBindQuery(&params)
	if err != nil {
		error.ParamsErrorResponse(c, err)
		return
	}

	domains, err := r.service.RetrieveDomainsByFilter(params)
	if err != nil {
		error.DatabaseErrorResponse(c, err)
		return
	}

	c.JSON(http.StatusOK, domains)
}

// PutBlackListedDomains accepts and saves list of blacklisted domains
//
// @Summary     insert blacklisted domains
// @Description Accepts and saves list of blacklisted domains
// @Tags        Blacklists
// @Router      /blacklists/domains [put]
// @Param       hosts body     blacklistInsertParams true "IPs to save"
// @Success     201   {object} success.DatabaseResponse
// @Failure     400   {object} error.APIError
func (r *BlacklistsRouter) PutBlackListedDomains(c *gin.Context) {
	var params blacklistInsertParams

	err := c.ShouldBindJSON(&params)
	if err != nil {
		error.ParamsErrorResponse(c, err)
		return
	}

	var domains []entities.BlacklistedDomain
	for _, h := range params.Hosts {
		domains = append(domains, entities.BlacklistedDomain{
			URN:      h.Host,
			SourceID: h.SourceID,
		})
	}

	rows, err := r.service.SaveDomains(domains)
	if err != nil {
		error.DatabaseErrorResponse(c, err)
		return
	}

	success.SavedResponse(c, rows)
}

// PutBlackListedIPs accepts and saves list of blacklisted IPs
//
// @Summary     insert blacklisted ips
// @Description Accepts and saves list of blacklisted IPs
// @Tags        Blacklists
// @Router      /blacklists/ips [put]
// @Param       hosts body     blacklistInsertParams    true "IPs to save"
// @Success     201   {object} success.DatabaseResponse true
// @Failure     400   {object} error.APIError
func (r *BlacklistsRouter) PutBlackListedIPs(c *gin.Context) {
	var params blacklistInsertParams

	err := c.ShouldBindJSON(&params)
	if err != nil {
		error.ParamsErrorResponse(c, err)
		return
	}

	var ips []entities.BlacklistedIP
	for _, h := range params.Hosts {
		var ipAddress = pgtype.Inet{}

		err = ipAddress.Set(h.Host)
		if err != nil {
			error.ParamsErrorResponse(c, err)
			return
		}

		ips = append(ips, entities.BlacklistedIP{
			IPAddress: ipAddress,
			SourceID:  h.SourceID,
		})
	}

	rows, err := r.service.SaveIPs(ips)
	if err != nil {
		error.DatabaseErrorResponse(c, err)
		return
	}

	success.SavedResponse(c, rows)
}

type blacklistInsertParams struct {
	Hosts []struct {
		Host     string `json:"host" binding:"required"`
		SourceID uint64 `json:"source_id" binding:"required"`
	} `json:"hosts" binding:"required,min=1,dive"` // issue: https://github.com/gin-gonic/gin/issues/3436
}

// DeleteBlackListedIP accepts and deletes single blacklisted IP
//
// @Summary     delete blacklisted ip
// @Description Accepts and deletes single blacklisted IP
// @Tags        Blacklists
// @Router      /blacklists/ip [delete]
// @Param       id  body     blacklistDeleteParams    true "record id to delete"
// @Success     200 {object} success.DatabaseResponse true
// @Failure     400 {object} error.APIError
func (r *BlacklistsRouter) DeleteBlackListedIP(c *gin.Context) {
	var params blacklistDeleteParams

	err := c.ShouldBindJSON(&params)
	if err != nil {
		error.ParamsErrorResponse(c, err)
		return
	}

	rows, err := r.service.DeleteIP(params.ID)
	if err != nil {
		error.DatabaseErrorResponse(c, err)
		return
	}

	success.DeletedResponse(c, rows)
}

// DeleteBlackListedDomain accepts and deletes single blacklisted domain
//
// @Summary     delete blacklisted domain
// @Description Accepts and deletes single blacklisted domain
// @Tags        Blacklists
// @Router      /blacklists/domain [delete]
// @Param       id  body     blacklistDeleteParams    true "record id to delete"
// @Success     200 {object} success.DatabaseResponse true
// @Failure     400 {object} error.APIError
func (r *BlacklistsRouter) DeleteBlackListedDomain(c *gin.Context) {
	var params blacklistDeleteParams

	err := c.ShouldBindJSON(&params)
	if err != nil {
		error.ParamsErrorResponse(c, err)
		return
	}

	rows, err := r.service.DeleteDomain(params.ID)
	if err != nil {
		error.DatabaseErrorResponse(c, err)
		return
	}

	success.DeletedResponse(c, rows)
}

type blacklistDeleteParams struct {
	ID uint64 `json:"id" binding:"required"`
}

// PostImportBlacklistsFromFinCERTFile accepts and imports blacklisted hosts from FinCERT file
//
// @Summary     import blacklisted hosts from file (FinCERT)
// @Description Accepts and imports blacklisted hosts from FinCERT file
// @Tags        Blacklists, Import
// @Router      /blacklists/import/fincert [post]
// @Param       import_file formData file                     true "file to import"
// @Success     201            {object} success.DatabaseResponse true
// @Failure     400         {object} error.APIError
func (r *BlacklistsRouter) PostImportBlacklistsFromFinCERTFile(c *gin.Context) {
	success.SavedResponse(c, 0)
}

// PostImportBlacklistsFromSTIXFile accepts and imports blacklisted hosts from STIX 2.0 file
//
// @Summary     import blacklisted hosts from file (STIX 2.0)
// @Description Accepts and imports blacklisted hosts from STIX 2.0 file
// @Tags        Blacklists, Import
// @Router      /blacklists/import/stix [post]
// @Param       import_file formData file                     true "file to import"
// @Success     201            {object} success.DatabaseResponse true
// @Failure     400            {object} error.APIError
func (r *BlacklistsRouter) PostImportBlacklistsFromSTIXFile(c *gin.Context) {
	success.SavedResponse(c, 0)
}

// PostExportBlacklistsToCSV accepts filters and returns exported blacklisted hosts in CSV
//
// @Summary     exports blacklisted hosts into CSV
// @Description Accepts filters and returns exported blacklisted hosts in CSV
// @Tags        Blacklists, Export
// @Router      /blacklists/export/csv [post]
// @Param       source_ids     query    []uint64                 false "Source type IDs" collectionFormat(multi)
// @Param       is_active      query    bool     false "Is active"
// @Param       created_after  query    string   false "Created timestamp is after"
// @Param       created_before query    string   false "Created timestamp is before"
// @Param       search_string  query    string                   false "Substring to search"
// @Param       limit          query    int      true  "Query limit"
// @Param       offset         query    int      false "Query offset"
// @Success     201         {object} success.DatabaseResponse true
// @Failure     400            {object} error.APIError
func (r *BlacklistsRouter) PostExportBlacklistsToCSV(c *gin.Context) {
	success.SavedResponse(c, 0)
}

// PostExportBlacklistsToJSON accepts filters and returns exported blacklisted hosts in JSON
//
// @Summary     exports blacklisted hosts into JSON
// @Description Accepts filters and returns exported blacklisted hosts in JSON
// @Tags        Blacklists, Export
// @Router      /blacklists/export/json [post]
// @Param       source_ids     query    []uint64                 false "Source type IDs" collectionFormat(multi)
// @Param       is_active      query    bool     false "Is active"
// @Param       created_after  query    string   false "Created timestamp is after"
// @Param       created_before query    string   false "Created timestamp is before"
// @Param       search_string  query    string   false "Substring to search"
// @Param       limit          query    int      true  "Query limit"
// @Param       offset         query    int      false "Query offset"
// @Success     201         {object} success.DatabaseResponse true
// @Failure     400            {object} error.APIError
func (r *BlacklistsRouter) PostExportBlacklistsToJSON(c *gin.Context) {
	success.SavedResponse(c, 0)
}
