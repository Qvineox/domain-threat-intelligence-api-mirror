package error

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

type APIError struct {
	StatusCode   uint64    `json:"status_code"`
	ErrorCode    CodeError `json:"error_code"`
	ErrorMessage string    `json:"error_message"`
	ErrorModule  string    `json:"error_module"`
}

type CodeError uint64

const (
	EncodingErrorCode CodeError = iota + 1
	DecodingErrorCode
	IncorrectParamsErrorCode
	InsufficientParamsErrorCode
)

func ParamsErrorResponse(c *gin.Context, err error) {
	c.JSON(http.StatusBadRequest, APIError{
		StatusCode:   http.StatusBadRequest,
		ErrorCode:    IncorrectParamsErrorCode,
		ErrorMessage: err.Error(),
		ErrorModule:  "rest endpoint",
	})
}
