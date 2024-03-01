package loggers

import (
	"fmt"
	"github.com/jackc/pgtype"
	"log/slog"
	"os"
	"path"
)

type DialerLogger struct {
	logger *slog.Logger

	dialerUUID *pgtype.UUID
	name       string
}

func NewDialerLogger(dialerUUID *pgtype.UUID, name string) DialerLogger {
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

	l = l.With(slog.String("dialer_name", name))

	return DialerLogger{logger: l}
}

func (l *DialerLogger) JobAssigned(jobUUID *pgtype.UUID) {
	l.logger.Info(
		"job assigned to agent",
		slog.String("job uuid", fmt.Sprintf("%x", jobUUID.Bytes)),
	)
}

func (l *DialerLogger) JobAssignmentFailed(jobUUID *pgtype.UUID, err error) {
	l.logger.Info(
		"job failed to assign to agent",
		slog.String("job uuid", fmt.Sprintf("%x", jobUUID.Bytes)),
		slog.String("error_message", err.Error()),
	)
}

func (l *DialerLogger) JobFinished(jobUUID *pgtype.UUID) {
	l.logger.Info(
		"job finished",
		slog.String("job uuid", fmt.Sprintf("%x", jobUUID.Bytes)),
		slog.String("error_message", ""),
	)
}

func (l *DialerLogger) MessageError(jobUUID *pgtype.UUID, err error) {
	l.logger.Info(
		"error handling message from agent",
		slog.String("job uuid", fmt.Sprintf("%x", jobUUID.Bytes)),
		slog.String("error_message", err.Error()),
	)
}
