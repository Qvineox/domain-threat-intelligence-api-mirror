package loggers

import (
	"log/slog"
)

type GORMLogger struct {
	slog.Logger
}
