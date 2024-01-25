package routing

import (
	error "domain_threat_intelligence_api/api/rest/error"
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
	TotalIPs     int64      `json:"TotalIPs"`
	ByDate       struct {
		Dates   []string `json:"Dates"`
		IPs     []uint64 `json:"IPs"`
		Domains []uint64 `json:"Domains"`
		URLs    []uint64 `json:"URLs"`
	} `json:"ByDate"`
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

	{
		blacklistsGroup.GET("/urls", router.GetBlackListedURLsByFilter)
		blacklistsGroup.PUT("/urls", router.PutBlackListedURLs)
		blacklistsGroup.DELETE("/url", router.DeleteBlackListedURL)
	}

	blacklistsGroup.GET("/hosts", router.GetBlackListedHostsByFilter)

	blacklistImportGroup := blacklistsGroup.Group("/import")

	{
		blacklistImportGroup.POST("/csv", router.PostImportBlacklistsFromCSVFile)
		blacklistImportGroup.POST("/stix", router.PostImportBlacklistsFromSTIXFile)
	}

	blacklistExportGroup := blacklistsGroup.Group("/export")

	{
		blacklistExportGroup.POST("/csv", router.PostExportBlacklistsToCSV)
		blacklistExportGroup.POST("/json", router.PostExportBlacklistsToJSON)
	}

	blacklistsGroup.GET("/sources", router.GetBlackListSources)
	blacklistsGroup.GET("/stats", router.GetStatistics)

	router.recountStatistics()

	return &router
}

// GetBlackListedHostsByFilter returns list of blacklisted hosts (all types) by filter
//
//	@Summary		all hosts by filter
//	@Description	Gets list of blacklisted hosts (all types) by filter
//	@Tags			Blacklists
//	@Router			/blacklists/hosts [get]
//	@Param			source_id[]		query		[]uint64	false	"Source type IDs"	collectionFormat(multi)
//	@Param			is_active		query		bool		false	"Is active"
//	@Param			created_after	query		string		false	"Created timestamp is after"
//	@Param			created_before	query		string		false	"Created timestamp is before"
//	@Param			search_string	query		string		false	"value to search"
//	@Param			limit			query		int			true	"Query limit"
//	@Param			offset			query		int			false	"Query offset"
//	@Success		200				{object}	[]blacklistEntities.BlacklistedHost
//	@Failure		400				{object}	error.APIError
func (r *BlacklistsRouter) GetBlackListedHostsByFilter(c *gin.Context) {
	params := blacklistEntities.BlacklistSearchFilter{}

	err := c.ShouldBindQuery(&params)
	if err != nil {
		error.ParamsErrorResponse(c, err)
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
		error.DatabaseErrorResponse(c, err)
		return
	}

	c.JSON(http.StatusOK, hosts)
}

// GetBlackListedIPsByFilter returns list of blacklisted IPs by filter
//
//	@Summary		blacklisted ips by filter
//	@Description	Gets list of blacklisted ips by filter
//	@Tags			Blacklists
//	@Router			/blacklists/ips [get]
//	@Param			source_id		query		[]uint64	false	"Source type IDs"	collectionFormat(multi)
//	@Param			is_active		query		bool		false	"Is active"
//	@Param			created_after	query		string		false	"Created timestamp is after"
//	@Param			created_before	query		string		false	"Created timestamp is before"
//	@Param			search_string	query		string		false	"CIDR to search (must include IP/MASK)"
//	@Param			limit			query		int			true	"Query limit"
//	@Param			offset			query		int			false	"Query offset"
//	@Success		200				{object}	[]blacklistEntities.BlacklistedIP
//	@Failure		400				{object}	error.APIError
func (r *BlacklistsRouter) GetBlackListedIPsByFilter(c *gin.Context) {
	params := blacklistEntities.BlacklistSearchFilter{}

	err := c.ShouldBindQuery(&params)
	if err != nil {
		error.ParamsErrorResponse(c, err)
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
//	@Summary		blacklisted domains by filter
//	@Description	Gets list of blacklisted domains by filter
//	@Tags			Blacklists
//	@Router			/blacklists/domains [get]
//	@Param			source_id		query		[]uint64	false	"Source type IDs"	collectionFormat(multi)
//	@Param			is_active		query		bool		false	"Is active"
//	@Param			created_after	query		string		false	"Created timestamp is after"
//	@Param			created_before	query		string		false	"Created timestamp is before"
//	@Param			search_string	query		string		false	"Substring to search"
//	@Param			limit			query		int			true	"Query limit"
//	@Param			offset			query		int			false	"Query offset"
//	@Success		200				{object}	[]blacklistEntities.BlacklistedDomain
//	@Failure		400				{object}	error.APIError
func (r *BlacklistsRouter) GetBlackListedDomainsByFilter(c *gin.Context) {
	params := blacklistEntities.BlacklistSearchFilter{}

	err := c.ShouldBindQuery(&params)
	if err != nil {
		error.ParamsErrorResponse(c, err)
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
		error.DatabaseErrorResponse(c, err)
		return
	}

	c.JSON(http.StatusOK, domains)
}

// GetBlackListedURLsByFilter returns list of blacklisted urls by filter
//
//	@Summary		blacklisted urls by filter
//	@Description	Gets list of blacklisted URLs by filter
//	@Tags			Blacklists
//	@Router			/blacklists/urls [get]
//	@Param			source_id		query		[]uint64	false	"Source type IDs"	collectionFormat(multi)
//	@Param			is_active		query		bool		false	"Is active"
//	@Param			created_after	query		string		false	"Created timestamp is after"
//	@Param			created_before	query		string		false	"Created timestamp is before"
//	@Param			search_string	query		string		false	"Substring to search"
//	@Param			limit			query		int			true	"Query limit"
//	@Param			offset			query		int			false	"Query offset"
//	@Success		200				{object}	[]blacklistEntities.BlacklistedURL
//	@Failure		400				{object}	error.APIError
func (r *BlacklistsRouter) GetBlackListedURLsByFilter(c *gin.Context) {
	params := blacklistEntities.BlacklistSearchFilter{}

	err := c.ShouldBindQuery(&params)
	if err != nil {
		error.ParamsErrorResponse(c, err)
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
		error.DatabaseErrorResponse(c, err)
		return
	}

	c.JSON(http.StatusOK, urls)
}

// PutBlackListedDomains accepts and saves list of blacklisted domains
//
//	@Summary		insert blacklisted domains
//	@Description	Accepts and saves list of blacklisted domains
//	@Tags			Blacklists
//	@Router			/blacklists/domains [put]
//	@Param			hosts	body		blacklistInsertParams	true	"IPs to save"
//	@Success		201		{object}	success.DatabaseResponse
//	@Failure		400		{object}	error.APIError
func (r *BlacklistsRouter) PutBlackListedDomains(c *gin.Context) {
	var params blacklistInsertParams

	err := c.ShouldBindJSON(&params)
	if err != nil {
		error.ParamsErrorResponse(c, err)
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
		error.DatabaseErrorResponse(c, err)
		return
	}

	success.SavedResponse(c, rows)
}

// PutBlackListedIPs accepts and saves list of blacklisted IPs
//
//	@Summary		insert blacklisted ips
//	@Description	Accepts and saves list of blacklisted IPs
//	@Tags			Blacklists
//	@Router			/blacklists/ips [put]
//	@Param			hosts	body		blacklistInsertParams	true	"IPs to save"
//	@Success		201		{object}	success.DatabaseResponse
//	@Failure		400		{object}	error.APIError
func (r *BlacklistsRouter) PutBlackListedIPs(c *gin.Context) {
	var params blacklistInsertParams

	err := c.ShouldBindJSON(&params)
	if err != nil {
		error.ParamsErrorResponse(c, err)
		return
	}

	var ips []blacklistEntities.BlacklistedIP
	for _, h := range params.Hosts {
		var ipAddress = pgtype.Inet{}

		err = ipAddress.Set(h.Host)
		if err != nil {
			error.ParamsErrorResponse(c, err)
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
		error.DatabaseErrorResponse(c, err)
		return
	}

	success.SavedResponse(c, rows)
}

// PutBlackListedURLs accepts and saves list of blacklisted URLs
//
//	@Summary		insert blacklisted urls
//	@Description	Accepts and saves list of blacklisted urls
//	@Tags			Blacklists
//	@Router			/blacklists/urls [put]
//	@Param			hosts	body		blacklistInsertParams	true	"URLs to save"
//	@Success		201		{object}	success.DatabaseResponse
//	@Failure		400		{object}	error.APIError
func (r *BlacklistsRouter) PutBlackListedURLs(c *gin.Context) {
	var params blacklistInsertParams

	err := c.ShouldBindJSON(&params)
	if err != nil {
		error.ParamsErrorResponse(c, err)
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
		error.DatabaseErrorResponse(c, err)
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
//	@Summary		delete blacklisted ip
//	@Description	Accepts and deletes single blacklisted IP
//	@Tags			Blacklists
//	@Router			/blacklists/ip [delete]
//	@Param			id	body		blacklistDeleteParams	true	"record UUID to delete"
//	@Success		200	{object}	success.DatabaseResponse
//	@Failure		400	{object}	error.APIError
func (r *BlacklistsRouter) DeleteBlackListedIP(c *gin.Context) {
	var params blacklistDeleteParams

	err := c.ShouldBindJSON(&params)
	if err != nil {
		error.ParamsErrorResponse(c, err)
		return
	}

	uuid := pgtype.UUID{}
	err = uuid.Set(params.UUID)
	if err != nil {
		error.ParamsErrorResponse(c, err)
		return
	}

	rows, err := r.service.DeleteIP(uuid)
	if err != nil {
		error.DatabaseErrorResponse(c, err)
		return
	}

	success.DeletedResponse(c, rows)
}

// DeleteBlackListedDomain accepts and deletes single blacklisted domain
//
//	@Summary		delete blacklisted domain
//	@Description	Accepts and deletes single blacklisted domain
//	@Tags			Blacklists
//	@Router			/blacklists/domain [delete]
//	@Param			id	body		blacklistDeleteParams	true	"record UUID to delete"
//	@Success		200	{object}	success.DatabaseResponse
//	@Failure		400	{object}	error.APIError
func (r *BlacklistsRouter) DeleteBlackListedDomain(c *gin.Context) {
	var params blacklistDeleteParams

	err := c.ShouldBindJSON(&params)
	if err != nil {
		error.ParamsErrorResponse(c, err)
		return
	}

	uuid := pgtype.UUID{}
	err = uuid.Set(params.UUID)
	if err != nil {
		error.ParamsErrorResponse(c, err)
		return
	}

	rows, err := r.service.DeleteDomain(uuid)
	if err != nil {
		error.DatabaseErrorResponse(c, err)
		return
	}

	success.DeletedResponse(c, rows)
}

// DeleteBlackListedURL accepts and deletes single blacklisted URL
//
//	@Summary		delete blacklisted URL
//	@Description	Accepts and deletes single blacklisted URL
//	@Tags			Blacklists
//	@Router			/blacklists/url [delete]
//	@Param			id	body		blacklistDeleteParams	true	"record UUID to delete"
//	@Success		200	{object}	success.DatabaseResponse
//	@Failure		400	{object}	error.APIError
func (r *BlacklistsRouter) DeleteBlackListedURL(c *gin.Context) {
	var params blacklistDeleteParams

	err := c.ShouldBindJSON(&params)
	if err != nil {
		error.ParamsErrorResponse(c, err)
		return
	}

	uuid := pgtype.UUID{}
	err = uuid.Set(params.UUID)
	if err != nil {
		error.ParamsErrorResponse(c, err)
		return
	}

	rows, err := r.service.DeleteURL(uuid)
	if err != nil {
		error.DatabaseErrorResponse(c, err)
		return
	}

	success.DeletedResponse(c, rows)
}

type blacklistDeleteParams struct {
	UUID string `json:"uuid" binding:"uuid4"`
}

// PostImportBlacklistsFromCSVFile accepts and imports blacklisted hosts from CSV file
//
//	@Summary		import blacklisted hosts from CSV file
//	@Description	Accepts and imports blacklisted hosts from CSV file
//	@Tags			Blacklists, Import
//	@Router			/blacklists/import/csv [post]
//	@Param			file_upload		formData	file	true	"file to import"
//	@Param			discovered_at	formData	string	true	"discovery date"
//	@Success		201				{object}	success.DatabaseResponse
//	@Failure		400				{object}	error.APIError
func (r *BlacklistsRouter) PostImportBlacklistsFromCSVFile(c *gin.Context) {
	form, err := c.MultipartForm()
	if err != nil {
		error.ParamsErrorResponse(c, err)
		return
	}

	files := form.File["file_upload"]

	var discoveredAt time.Time
	if len(form.Value["discovered_at"]) == 1 {
		discoveredAt, err = time.Parse("2006-01-02", form.Value["discovered_at"][0])
		if err != nil {
			error.ParamsErrorResponse(c, err)
			return
		}
	} else {
		discoveredAt = time.Now()
	}

	if len(files) == 0 {
		error.ParamsErrorResponse(c, errors.New("files not provided"))
		return
	}

	var rows int64
	for _, f := range files {
		switch filepath.Ext(f.Filename) {
		case ".csv":
			openedFile, err := f.Open()
			if err != nil {
				error.FileDecodingErrorResponse(c, err)
				return
			}

			csvReader := csv.NewReader(openedFile)
			data, err := csvReader.ReadAll()
			if err != nil {
				error.FileReadingErrorResponse(c, err)
				return
			}

			rows_, errs := r.service.ImportFromCSV(data, discoveredAt)
			if len(errs) > 0 {
				if rows == 0 {
					error.DatabaseMultipleErrorsResponse(c, errs)
				} else {
					success.SavedResponseWithWarnings(c, rows, errs)
				}

				return
			}

			rows += rows_
		default:
			error.FileExtensionNotSupportedErrorResponse(c, errors.New("file extension not supported"))
			return
		}
	}

	go r.recountStatistics()

	success.SavedResponse(c, rows)
}

// PostImportBlacklistsFromSTIXFile accepts and imports blacklisted hosts from STIX 2.0 file
//
//	@Summary		import blacklisted hosts from file (STIX 2.0)
//	@Description	Accepts and imports blacklisted hosts from STIX 2.0 file
//	@Tags			Blacklists, Import
//	@Accept			mpfd
//	@Router			/blacklists/import/stix [post]
//	@Param			file_upload	formData	file	true	"files to import"
//	@Success		201			{object}	success.DatabaseResponse
//	@Failure		400			{object}	error.APIError
func (r *BlacklistsRouter) PostImportBlacklistsFromSTIXFile(c *gin.Context) {
	form, err := c.MultipartForm()
	if err != nil {
		error.ParamsErrorResponse(c, err)
		return
	}

	files := form.File["file_upload"]
	if len(files) == 0 {
		error.ParamsErrorResponse(c, errors.New("files not provided"))
		return
	}

	var bundles []blacklistEntities.STIX2Bundle

	for _, f := range files {
		var bundle blacklistEntities.STIX2Bundle

		openedFile, err := f.Open()
		if err != nil {
			error.FileDecodingErrorResponse(c, err)
			return
		}

		file, err := io.ReadAll(openedFile)
		if err != nil {
			error.FileReadingErrorResponse(c, err)
			return
		}

		switch filepath.Ext(f.Filename) {
		case ".json":
			err = json.Unmarshal(file, &bundle)
			if err != nil {
				error.FileDecodingErrorResponse(c, err)
				return
			}

			if len(bundle.ID) == 0 {
				error.FileDecodingErrorResponse(c, errors.New("bundles not found"))
				return
			}

			bundles = append(bundles, bundle)
		default:
			error.FileExtensionNotSupportedErrorResponse(c, errors.New("file extension not supported"))
			return
		}
	}

	rows, errs := r.service.ImportFromSTIX2(bundles)
	if len(errs) > 0 {
		if rows == 0 {
			error.DatabaseMultipleErrorsResponse(c, errs)
		} else {
			success.SavedResponseWithWarnings(c, rows, errs)
		}

		return
	}

	go r.recountStatistics()

	success.SavedResponse(c, rows)
}

// PostExportBlacklistsToCSV accepts filters and returns exported blacklisted hosts in CSV
//
//	@Summary		exports blacklisted hosts into CSV
//	@Description	Accepts filters and returns exported blacklisted hosts in CSV
//	@Tags			Blacklists, Export
//	@Router			/blacklists/export/csv [post]
//	@Param			source_ids[]	query	[]uint64	false	"Source type IDs"	collectionFormat(multi)
//	@Param			created_after	query	string		true	"Created timestamp is after"
//	@Param			created_before	query	string		true	"Created timestamp is before"
//	@Produce		application/csv
//	@Success		200	{file}		file
//	@Failure		400	{object}	error.APIError
func (r *BlacklistsRouter) PostExportBlacklistsToCSV(c *gin.Context) {
	params := blacklistEntities.BlacklistExportFilter{}

	err := c.ShouldBindQuery(&params)
	if err != nil {
		error.ParamsErrorResponse(c, err)
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

	jsonBytes, err := r.service.ExportToCSV(params)
	if err != nil {
		error.FileProcessingErrorResponse(c, err)
		return
	}

	pattern := fmt.Sprintf("export_%d.*.csv", time.Now().Unix())
	file, err := os.CreateTemp("", pattern)
	if err != nil {
		error.FileProcessingErrorResponse(c, err)
		return
	}
	defer os.Remove(file.Name())

	_, err = file.Write(jsonBytes)
	if err != nil {
		error.FileProcessingErrorResponse(c, err)
		return
	}

	c.FileAttachment(file.Name(), filepath.Base(file.Name()))
}

// PostExportBlacklistsToJSON accepts filters and returns exported blacklisted hosts in JSON. ref: https://github.com/swaggo/swag/issues/726
//
//	@Summary		exports blacklisted hosts into JSON
//	@Description	Accepts filters and returns exported blacklisted hosts in JSON
//	@Tags			Blacklists, Export
//	@Router			/blacklists/export/json [post]
//	@Param			source_ids		query	[]uint64	false	"Source type IDs"	collectionFormat(multi)
//	@Param			created_after	query	string		true	"Created timestamp is after"
//	@Param			created_before	query	string		true	"Created timestamp is before"
//	@Produce		application/json
//	@Success		200	{file}		file
//	@Failure		400	{object}	error.APIError
func (r *BlacklistsRouter) PostExportBlacklistsToJSON(c *gin.Context) {
	params := blacklistEntities.BlacklistExportFilter{}

	err := c.ShouldBindQuery(&params)
	if err != nil {
		error.ParamsErrorResponse(c, err)
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

	jsonBytes, err := r.service.ExportToJSON(params)
	if err != nil {
		error.FileProcessingErrorResponse(c, err)
		return
	}

	pattern := fmt.Sprintf("export_%d.*.json", time.Now().Unix())
	file, err := os.CreateTemp("", pattern)
	if err != nil {
		error.FileProcessingErrorResponse(c, err)
		return
	}
	defer os.Remove(file.Name())

	_, err = file.Write(jsonBytes)
	if err != nil {
		error.FileProcessingErrorResponse(c, err)
		return
	}

	c.FileAttachment(file.Name(), filepath.Base(file.Name()))
}

// GetStatistics returns data containing overall amount of blacklisted entities
//
//	@Summary		returns amount of blacklisted entities
//	@Description	Returns data containing overall amount of blacklisted entities
//	@Tags			Blacklists
//	@Router			/blacklists/stats [get]
//	@Produce		application/json
//	@Success		200	{object}	BlacklistedStatistics
//	@Failure		400	{object}	error.APIError
func (r *BlacklistsRouter) GetStatistics(c *gin.Context) {
	if r.cachedValues.stats.LastEval == nil || r.cachedValues.stats.LastEval.Before(time.Now().Add(-2*time.Hour)) {
		r.recountStatistics()
	}

	c.JSON(http.StatusOK, r.cachedValues.stats)
}

// GetBlackListSources returns all blacklists source types
//
//	@Summary		returns blacklist sources
//	@Description	Returns all available blacklist data sources
//	@Tags			Blacklists
//	@Router			/blacklists/sources [get]
//	@Produce		application/json
//	@Success		200	{object}	[]blacklistEntities.BlacklistSource
//	@Failure		400	{object}	error.APIError
func (r *BlacklistsRouter) GetBlackListSources(c *gin.Context) {
	sources, err := r.service.RetrieveAllSources()
	if err != nil {
		error.DatabaseErrorResponse(c, err)
		return
	}

	c.JSON(http.StatusOK, sources)
}

func (r *BlacklistsRouter) recountStatistics() {
	now := time.Now()
	r.cachedValues.stats.LastEval = &now

	r.cachedValues.stats.TotalIPs, r.cachedValues.stats.TotalURLs, r.cachedValues.stats.TotalDomains = r.service.RetrieveTotalStatistics()

	//var byDate = make(map[string]*[3]uint64)

	statistics, err := r.service.RetrieveByDateStatistics(now.Add(-time.Hour*24*31*6), now)
	if err != nil {
		return
	}

	var stats = struct {
		Dates   []string `json:"Dates"`
		IPs     []uint64 `json:"IPs"`
		Domains []uint64 `json:"Domains"`
		URLs    []uint64 `json:"URLs"`
	}{
		Dates:   make([]string, 0),
		IPs:     make([]uint64, 0),
		Domains: make([]uint64, 0),
		URLs:    make([]uint64, 0),
	}

	for _, v := range statistics {
		date := v.Date.Format("02.01.2006")

		index := slices.Index(stats.Dates, date)
		if index == -1 {
			stats.Dates = append(stats.Dates, date)
			index = len(stats.Dates) - 1

			stats.URLs = append(stats.URLs, 0)
			stats.IPs = append(stats.IPs, 0)
			stats.Domains = append(stats.Domains, 0)
		}

		switch v.Type {
		case "url":
			stats.URLs[index] = v.Count
		case "ip":
			stats.IPs[index] = v.Count
		case "domain":
			stats.Domains[index] = v.Count
		}
	}

	r.cachedValues.stats.ByDate = stats
}
