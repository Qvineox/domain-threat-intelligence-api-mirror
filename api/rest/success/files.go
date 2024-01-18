package success

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

type FilesResponse struct {
	StatusCode uint64   `json:"status_code"`
	FileFields []string `json:"file_fields"`
}

func FilesServedResponse(c *gin.Context, fields []string) {
	c.JSON(http.StatusCreated, FilesResponse{
		StatusCode: http.StatusCreated,
		FileFields: fields,
	})
}
