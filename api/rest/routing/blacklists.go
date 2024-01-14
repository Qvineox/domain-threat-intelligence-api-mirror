package routing

import (
	"domain_threat_intelligence_api/api/rest/error"
	"domain_threat_intelligence_api/api/rest/success"
	"github.com/gin-gonic/gin"
	"net/http"
	"time"
)

func HandleBlacklistsGroup(path *gin.RouterGroup) {
	blacklistsGroup := path.Group("/blacklists")

	{
		blacklistsGroup.GET("/ips", GetBlackListedIPsByFilter)
		blacklistsGroup.PUT("/ips", PutBlackListedIPs)
		blacklistsGroup.DELETE("/ip", DeleteBlackListedIP)
	}

	{
		blacklistsGroup.GET("/domains", GetBlackListedDomainsByFilter)
		blacklistsGroup.PUT("/domains", PutBlackListedDomains)
		blacklistsGroup.DELETE("/domain", DeleteBlackListedDomain)
	}

	blacklistImportGroup := blacklistsGroup.Group("/import")

	{
		blacklistImportGroup.POST("/fincert", PostImportBlacklistsFromFinCERTFile)
		blacklistImportGroup.POST("/stix", PostImportBlacklistsFromSTIXFile)
	}
}

// GetBlackListedIPsByFilter returns list of blacklisted IPs by filter
//
// @Summary     blacklisted ips by filter
// @Description Gets list of blacklisted ips by filter
// @Tags        Blacklists
// @Router      /blacklists/ips [get]
// @Param       source_id      query    uint64 false "Source type ID"
// @Param       is_active      query    bool   false "Is active"
// @Param       created_after  query    string false "Created timestamp is after"
// @Param       created_before query    string false "Created timestamp is before"
// @Param       search_string  query    string false "Substring to search"
// @Param       limit          query    uint64 false "Query limit"
// @Param       offset         query    uint64 false "Query offset"
// @Success     200            {object} []entities.BlacklistedIP
// @Failure     400         {object} error.APIError
func GetBlackListedIPsByFilter(c *gin.Context) {
	params := blackListsFilter{}

	err := c.ShouldBind(&params)
	if err != nil {
		error.ParamsErrorResponse(c, err)
		return
	}
}

// GetBlackListedDomainsByFilter returns list of blacklisted domains by filter
//
// @Summary     blacklisted domains by filter
// @Description Gets list of blacklisted domains by filter
// @Tags        Blacklists
// @Router      /blacklists/domains [get]
// @Param       source_id      query    uint64 false "Source type ID"
// @Param       is_active      query    bool   false "Is active"
// @Param       created_after  query    string false "Created timestamp is after"
// @Param       created_before query    string false "Created timestamp is before"
// @Param       search_string  query    string false "Substring to search"
// @Param       limit          query    uint64 false "Query limit"
// @Param       offset         query    uint64 false "Query offset"
// @Success     200            {object} []entities.BlacklistedDomain
// @Failure     400         {object} error.APIError
func GetBlackListedDomainsByFilter(c *gin.Context) {
	params := blackListsFilter{}

	err := c.ShouldBind(&params)
	if err != nil {
		error.ParamsErrorResponse(c, err)
		return
	}

	c.JSON(http.StatusOK, "good!")
}

type blackListsFilter struct {
	SourceID      uint64    `json:"source_id" form:"source_id"`
	IsActive      bool      `json:"is_active" form:"is_active"`
	CreatedAfter  time.Time `json:"created_after" form:"created_after" time_format:"2006-01-02"`
	CreatedBefore time.Time `json:"created_before" form:"created_before" time_format:"2006-01-02"`
	Substring     string    `json:"search_string" form:"search_string"`
	Offset        uint64    `json:"offset" form:"offset"`
	Limit         uint64    `json:"limit" form:"limit" binding:"required"`
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
func PutBlackListedDomains(c *gin.Context) {
	var params blacklistInsertParams

	err := c.ShouldBindJSON(&params)
	if err != nil {
		error.ParamsErrorResponse(c, err)
		return
	}

	success.SavedResponse(c, 0)
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
func PutBlackListedIPs(c *gin.Context) {
	var params blacklistInsertParams

	err := c.ShouldBindJSON(&params)
	if err != nil {
		error.ParamsErrorResponse(c, err)
		return
	}

	success.SavedResponse(c, 0)
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
func DeleteBlackListedIP(c *gin.Context) {
	var params blacklistDeleteParams

	err := c.ShouldBindJSON(&params)
	if err != nil {
		error.ParamsErrorResponse(c, err)
		return
	}

	success.DeletedResponse(c, 0)
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
func DeleteBlackListedDomain(c *gin.Context) {
	var params blacklistDeleteParams

	err := c.ShouldBindJSON(&params)
	if err != nil {
		error.ParamsErrorResponse(c, err)
		return
	}

	success.DeletedResponse(c, 0)
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
// @Success     201         {object} success.DatabaseResponse true
// @Failure     400            {object} error.APIError
func PostImportBlacklistsFromFinCERTFile(c *gin.Context) {
	success.SavedResponse(c, 0)
}

// PostImportBlacklistsFromSTIXFile accepts and imports blacklisted hosts from STIX 2.0 file
//
// @Summary     import blacklisted hosts from file (STIX 2.0)
// @Description Accepts and imports blacklisted hosts from STIX 2.0 file
// @Tags        Blacklists, Import
// @Router      /blacklists/import/stix [post]
// @Param       import_file formData file                     true "file to import"
// @Success     201         {object} success.DatabaseResponse true
// @Failure     400            {object} error.APIError
func PostImportBlacklistsFromSTIXFile(c *gin.Context) {
	success.SavedResponse(c, 0)
}
