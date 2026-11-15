package router

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"

	"github.com/labstack/echo/v5"

	log "github.com/sirupsen/logrus"
)

// echoLogHandler routes Echo's slog diagnostics through the application logger.
// The message and attributes can include request data, so only known static
// Echo messages and a coarse error category are emitted.
type echoLogHandler struct {
	attrs []slog.Attr
}

func echoLevel(level slog.Level) log.Level {
	switch {
	case level >= slog.LevelError:
		return log.ErrorLevel
	case level >= slog.LevelWarn:
		return log.WarnLevel
	case level >= slog.LevelInfo:
		return log.InfoLevel
	default:
		return log.DebugLevel
	}
}

func (h *echoLogHandler) Enabled(_ context.Context, level slog.Level) bool {
	return log.IsLevelEnabled(echoLevel(level))
}

func (h *echoLogHandler) Handle(_ context.Context, record slog.Record) error {
	fields := log.Fields{"event": "echo.diagnostic", "source": "echo"}
	for _, attr := range h.attrs {
		addSafeEchoAttr(fields, attr)
	}
	record.Attrs(func(attr slog.Attr) bool {
		addSafeEchoAttr(fields, attr)
		return true
	})
	message := "Echo diagnostic"
	switch record.Message {
	case "echo: response already written to client":
		message = "Echo response already written to client"
	case "echo default error handler failed to send error to client":
		message = "Echo error handler failed to send response"
	case "echo RFC 9457 error handler failed to send error to client":
		message = "Echo RFC 9457 error handler failed to send response"
	case "failed to shut down server within given timeout":
		message = "Echo server shutdown timed out"
	}
	entry := log.WithFields(fields)
	if !record.Time.IsZero() {
		entry = entry.WithTime(record.Time)
	}
	entry.Log(echoLevel(record.Level), message)
	return nil
}

func addSafeEchoAttr(fields log.Fields, attr slog.Attr) {
	value := attr.Value.Resolve()
	if value.Kind() == slog.KindGroup {
		for _, nested := range value.Group() {
			addSafeEchoAttr(fields, nested)
		}
		return
	}
	if attr.Key != "error" || value.Kind() != slog.KindAny {
		return
	}
	if err, ok := value.Any().(error); ok && err != nil {
		fields["error"] = safeEchoError(err)
	}
}

// safeEchoError preserves common operational categories without accepting
// arbitrary error text that can contain request URLs or payloads.
func safeEchoError(err error) string {
	var httpError *echo.HTTPError
	switch {
	case errors.Is(err, context.Canceled):
		return "request canceled"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		return "deadline exceeded"
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "unexpected end of stream"
	case errors.Is(err, io.EOF):
		return "end of stream"
	case errors.As(err, &httpError):
		if text := http.StatusText(httpError.Code); text != "" {
			return text
		}
	}
	return "request failed"
}

func (h *echoLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	copyAttrs := append([]slog.Attr(nil), h.attrs...)
	copyAttrs = append(copyAttrs, attrs...)
	return &echoLogHandler{attrs: copyAttrs}
}

func (h *echoLogHandler) WithGroup(_ string) slog.Handler {
	// Names are intentionally discarded with the other untrusted metadata.
	return &echoLogHandler{attrs: append([]slog.Attr(nil), h.attrs...)}
}
