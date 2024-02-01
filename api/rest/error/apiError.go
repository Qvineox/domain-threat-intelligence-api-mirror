package error

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
)

type APIError struct {
	StatusCode   uint64    `json:"StatusCode"`
	ErrorCode    CodeError `json:"ErrorCode"`
	ErrorMessage string    `json:"ErrorMessage"`
	ErrorModule  string    `json:"ErrorModule"`
}

type CodeError uint64

const (
	EncodingErrorCode CodeError = iota + 1
	DecodingErrorCode
	IncorrectParamsErrorCode
	InsufficientParamsErrorCode
	DatabaseErrorCode
	FileDecodingErrorCode
	FileReadingErrorCode
	FileExtensionNotSupportedErrorCode
	NotImplementedErrorCode
	FileProcessingErrorCode
	InternalUnidentifiedErrorCode
	AuthFailedErrorCode
)

func ParamsErrorResponse(c *gin.Context, err error) {
	c.JSON(http.StatusBadRequest, APIError{
		StatusCode:   http.StatusBadRequest,
		ErrorCode:    IncorrectParamsErrorCode,
		ErrorMessage: err.Error(),
		ErrorModule:  "rest endpoint",
	})
}

func DatabaseErrorResponse(c *gin.Context, err error) {
	c.JSON(http.StatusBadRequest, APIError{
		StatusCode:   http.StatusBadRequest,
		ErrorCode:    DatabaseErrorCode,
		ErrorMessage: err.Error(),
		ErrorModule:  "database operations",
	})
}

func DatabaseMultipleErrorsResponse(c *gin.Context, errs []error) {
	var errors []string
	for _, e := range errs {
		errors = append(errors, e.Error())
	}

	c.JSON(http.StatusBadRequest, APIError{
		StatusCode:   http.StatusBadRequest,
		ErrorCode:    DatabaseErrorCode,
		ErrorMessage: strings.Join(errors, ";"),
		ErrorModule:  "database operations",
	})
}

func FileDecodingErrorResponse(c *gin.Context, err error) {
	c.JSON(http.StatusBadRequest, APIError{
		StatusCode:   http.StatusBadRequest,
		ErrorCode:    FileDecodingErrorCode,
		ErrorMessage: err.Error(),
		ErrorModule:  "file handling",
	})
}

func FileReadingErrorResponse(c *gin.Context, err error) {
	c.JSON(http.StatusBadRequest, APIError{
		StatusCode:   http.StatusBadRequest,
		ErrorCode:    FileReadingErrorCode,
		ErrorMessage: err.Error(),
		ErrorModule:  "file handling",
	})
}

func FileExtensionNotSupportedErrorResponse(c *gin.Context, err error) {
	c.JSON(http.StatusNotAcceptable, APIError{
		StatusCode:   http.StatusNotAcceptable,
		ErrorCode:    FileExtensionNotSupportedErrorCode,
		ErrorMessage: err.Error(),
		ErrorModule:  "file handling",
	})
}

func NotImplementedErrorResponse(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, APIError{
		StatusCode:   http.StatusNotImplemented,
		ErrorCode:    NotImplementedErrorCode,
		ErrorMessage: "service not implemented",
		ErrorModule:  "rest endpoint",
	})
}

func FileProcessingErrorResponse(c *gin.Context, err error) {
	c.JSON(http.StatusInternalServerError, APIError{
		StatusCode:   http.StatusInternalServerError,
		ErrorCode:    FileProcessingErrorCode,
		ErrorMessage: err.Error(),
		ErrorModule:  "file processing",
	})
}

func InternalErrorResponse(c *gin.Context, err error) {
	c.JSON(http.StatusInternalServerError, APIError{
		StatusCode:   http.StatusInternalServerError,
		ErrorCode:    InternalUnidentifiedErrorCode,
		ErrorMessage: err.Error(),
		ErrorModule:  "internal process",
	})
}

func AuthErrorResponse(c *gin.Context, err error) {
	c.JSON(http.StatusUnauthorized, APIError{
		StatusCode:   http.StatusUnauthorized,
		ErrorCode:    AuthFailedErrorCode,
		ErrorMessage: err.Error(),
		ErrorModule:  "authorization",
	})
}
