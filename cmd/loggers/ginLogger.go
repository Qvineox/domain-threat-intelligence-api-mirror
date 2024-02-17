package loggers

import (
	"context"
	"github.com/gin-gonic/gin"
	"log/slog"
	"os"
	"time"
)

type GINLogger struct {
	logger *slog.Logger
}

func NewGINLogger() *GINLogger {
	l := GINLogger{logger: slog.New(slog.NewJSONHandler(os.Stdout, nil))}

	return &l
}

func (l *GINLogger) ProvideMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		path := c.Request.URL.Path

		// Process request
		c.Next()

		// Fill the params
		param := gin.LogFormatterParams{}

		param.TimeStamp = time.Now() // Stop timer
		param.Latency = param.TimeStamp.Sub(start)
		if param.Latency > time.Minute {
			param.Latency = param.Latency.Truncate(time.Second)
		}

		param.ClientIP = c.ClientIP()
		param.Method = c.Request.Method
		param.StatusCode = c.Writer.Status()
		param.ErrorMessage = c.Errors.ByType(gin.ErrorTypePrivate).String()
		param.Path = path

		// Log using the params
		var level slog.Level

		if c.Writer.Status() >= 500 {
			level = slog.LevelError
		} else if c.Writer.Status() >= 400 {
			level = slog.LevelWarn
		} else {
			level = slog.LevelInfo
		}

		l.logger.LogAttrs(
			context.Background(),
			level,
			"request received",
			slog.String("path", param.Path),
			slog.String("method", param.Method),
			slog.String("client_ip", param.ClientIP),
			slog.String("latency", param.Latency.String()),
			slog.Int("status", param.StatusCode),
			slog.String("error_message", param.ErrorMessage),
		)
	}
}
