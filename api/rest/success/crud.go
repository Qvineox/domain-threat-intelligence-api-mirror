package success

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

type DatabaseResponse struct {
	StatusCode   uint64 `json:"status_code"`
	RowsAffected uint64 `json:"rows_affected"`
}

func SavedResponse(c *gin.Context, rows uint64) {
	c.JSON(http.StatusCreated, DatabaseResponse{
		StatusCode:   http.StatusCreated,
		RowsAffected: rows,
	})
}

func DeletedResponse(c *gin.Context, rows uint64) {
	c.JSON(http.StatusOK, DatabaseResponse{
		StatusCode:   http.StatusOK,
		RowsAffected: rows,
	})
}
