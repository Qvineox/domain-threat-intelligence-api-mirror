package success

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

type DatabaseResponse struct {
	StatusCode   uint64   `json:"status_code"`
	RowsAffected int64    `json:"rows_affected"`
	Warnings     []string `json:"warnings,omitempty"`
}

func SavedResponse(c *gin.Context, rows int64) {
	c.JSON(http.StatusCreated, DatabaseResponse{
		StatusCode:   http.StatusCreated,
		RowsAffected: rows,
	})
}

func SavedResponseWithWarnings(c *gin.Context, rows int64, errs []error) {
	var errors []string
	for _, e := range errs {
		errors = append(errors, e.Error())
	}

	c.JSON(http.StatusCreated, DatabaseResponse{
		StatusCode:   http.StatusCreated,
		RowsAffected: rows,
		Warnings:     errors,
	})
}

func DeletedResponse(c *gin.Context, rows int64) {
	c.JSON(http.StatusOK, DatabaseResponse{
		StatusCode:   http.StatusOK,
		RowsAffected: rows,
	})
}
