package loggers

import (
	"log/slog"
	"os"
	"path"
)

func SetDefaultLogger(level slog.Level) {
	dl := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		AddSource: true,
		Level:     level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.SourceKey {
				s := a.Value.Any().(*slog.Source)
				s.File = path.Base(s.File)
				s.Function = path.Base(s.Function)
			}

			return a
		},
	}))

	slog.SetDefault(dl)
}
