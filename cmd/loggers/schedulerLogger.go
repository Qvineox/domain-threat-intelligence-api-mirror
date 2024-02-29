package loggers

import (
	"fmt"
	"github.com/jackc/pgtype"
	"log/slog"
	"os"
	"path"
)

type SchedulerLogger struct {
	logger *slog.Logger
}

func NewSchedulerLogger() *SchedulerLogger {
	l := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		AddSource: false,
		Level:     slog.LevelInfo,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.SourceKey {
				s := a.Value.Any().(*slog.Source)
				s.File = path.Base(s.File)
				s.Function = path.Base(s.Function)
			}

			return a
		},
	}))

	l = l.With(slog.String("log_type", "scheduler"))

	return &SchedulerLogger{logger: l}
}

func (l *SchedulerLogger) JobAssigned(jobUUID, agentUUID pgtype.UUID, agentName string) {
	l.logger.Info(
		"job assigned to agent",
		slog.String("job uuid", fmt.Sprintf("%x", jobUUID.Bytes)),
		slog.String("agent name", agentName),
		slog.String("agent uuid", fmt.Sprintf("%x", agentUUID.Bytes)),
		slog.String("error_message", ""),
	)
}

func (l *SchedulerLogger) JobAssignmentFailed(jobUUID, agentUUID pgtype.UUID, agentName string, err error) {
	l.logger.Info(
		"job failed to assign to agent",
		slog.String("job uuid", fmt.Sprintf("%x", jobUUID.Bytes)),
		slog.String("agent name", agentName),
		slog.String("agent uuid", fmt.Sprintf("%x", agentUUID.Bytes)),
		slog.String("error_message", err.Error()),
	)
}

func (l *SchedulerLogger) MessageError(jobUUID, agentUUID pgtype.UUID, agentName string, err error) {
	l.logger.Info(
		"error handling message from agent",
		slog.String("job uuid", fmt.Sprintf("%x", jobUUID.Bytes)),
		slog.String("agent name", agentName),
		slog.String("agent uuid", fmt.Sprintf("%x", agentUUID.Bytes)),
		slog.String("error_message", err.Error()),
	)
}

func (l *SchedulerLogger) NoHandlersAvailable(jobUUID pgtype.UUID) {
	l.logger.Info(
		"no handlers available",
		slog.String("job uuid", fmt.Sprintf("%x", jobUUID.Bytes)),
		slog.String("agent name", ""),
		slog.String("agent uuid", ""),
		slog.String("error_message", "no handlers available"),
	)
}
