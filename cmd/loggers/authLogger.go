package loggers

import (
	"log/slog"
	"os"
	"path"
)

type AuthLogger struct {
	logger *slog.Logger
}

func NewAuthLogger() *AuthLogger {
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

	l = l.With(slog.String("log_type", "auth"))

	return &AuthLogger{logger: l}
}

func (l *AuthLogger) SessionLogin(login, address string, id uint64, err error) {
	if err != nil {
		l.logger.Warn(
			"user failed to login",
			slog.Uint64("id", id),
			slog.String("login", login),
			slog.String("address", address),
			slog.String("error", err.Error()),
		)
	} else {
		l.logger.Info(
			"user logged in",
			slog.Uint64("id", id),
			slog.String("login", login),
			slog.String("address", address),
			slog.String("error", ""),
		)
	}
}

func (l *AuthLogger) SessionLogout(login, address string, id uint64, err error) {
	if err != nil {
		l.logger.Warn(
			"user failed logged out",
			slog.Uint64("id", id),
			slog.String("login", login),
			slog.String("address", address),
			slog.String("error", err.Error()),
		)
	} else {
		l.logger.Info(
			"user logged out",
			slog.Uint64("id", id),
			slog.String("login", login),
			slog.String("address", address),
			slog.String("error", ""),
		)
	}
}

func (l *AuthLogger) SessionRefresh(login, address string, id uint64, err error) {
	if err != nil {
		l.logger.Warn(
			"user session refreshed",
			slog.Uint64("id", id),
			slog.String("login", login),
			slog.String("address", address),
			slog.String("error", err.Error()),
		)
	} else {
		l.logger.Info(
			"user session interrupted",
			slog.Uint64("id", id),
			slog.String("login", login),
			slog.String("address", address),
			slog.String("error", ""),
		)
	}
}
