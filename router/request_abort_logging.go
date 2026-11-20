package router

import (
	"net/http"

	"github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v5"
	log "github.com/sirupsen/logrus"
)

// observeRequestAbort records requests that unwind before the request logger
// can complete. It never writes a response or changes net/http's panic policy.
func observeRequestAbort(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) (err error) {
		completed := false
		func() {
			defer func() {
				if value := recover(); value != nil {
					logRequestAbort(c, value == http.ErrAbortHandler)
					panic(value)
				}
			}()
			err = next(c)
			completed = true
		}()
		if !completed {
			// With GODEBUG=panicnil=1, a recovered panic(nil) yields nil.
			// Goexit cannot reach this branch: it continues terminating the
			// goroutine after deferred functions return.
			logRequestAbort(c, false)
			panic(nil)
		}
		return err
	}
}

// A failed diagnostic must not replace the original panic, whose handling is
// owned by net/http. Panic values and stacks may contain credentials or input
// from a remote peer and must never be copied into the audit record.
func logRequestAbort(c *echo.Context, intentional bool) {
	defer func() { _ = recover() }()
	fields := utils.AuditRequestFields(c)
	if c != nil {
		if response, err := echo.UnwrapResponse(c.Response()); err == nil && response != nil {
			fields["response_committed"] = response.Committed
			if response.Committed && c.Path() == utils.DownloadSessionRoute {
				fields["status"] = response.Status
				fields["bytes_out"] = response.Size
			}
		}
	}
	if intentional {
		fields["event"] = "http.request_aborted"
		fields["reason_class"] = "abort_handler"
		log.WithFields(fields).Warn("HTTP request aborted")
		return
	}
	fields["event"] = "http.request_panic"
	fields["reason_class"] = "handler_panic"
	log.WithFields(fields).Error("HTTP request panicked")
}
