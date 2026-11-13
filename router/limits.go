package router

import (
	"bytes"
	"errors"
	"io"
	"math"
	"mime"
	"net/http"
	"time"

	"github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v4"
	log "github.com/sirupsen/logrus"
)

const (
	defaultIOIdleTimeout  = 2 * time.Minute
	maxSmallRequestBytes  = 64 << 10
	maxConcurrentRequests = 64
	maxConcurrentUploads  = 4
	maxSmallBodyTime      = 30 * time.Second
	maxUploadBodyBytes    = int64(1024 * 1000 * 1000) // Echo BodyLimit("1024M") uses decimal MB.
	uploadRateGrace       = 30 * time.Second
	minUploadBytesPerSec  = int64(32 << 10)
)

// Shared across router instances, so constructing another router does not
// accidentally multiply the process-wide request budget.
var requestSlots = make(chan struct{}, maxConcurrentRequests)
var uploadSlots = make(chan struct{}, maxConcurrentUploads)

// On HTTP/1, avoid net/http draining a slow unfinished request body before it
// can send an error response. HTTP/2 manages cancellation per stream instead.
func closeUnreadHTTP1(c echo.Context) {
	if r := c.Request(); r.ProtoMajor == 1 && r.Body != nil && r.Body != http.NoBody {
		c.Response().Header().Set(echo.HeaderConnection, "close")
	}
}

func multipartFileUpload(r *http.Request) bool {
	if r.Method != http.MethodPost || (r.URL.Path != "/file" && r.URL.Path != "/file/") {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get(echo.HeaderContentType))
	return err == nil && mediaType == echo.MIMEMultipartForm
}

// requestLimits executes before CSRF parsing. File uploads keep their existing
// streaming body limit; all other unsafe requests are buffered only up to a
// small, finite size so chunked input cannot bypass the limit.
func requestLimits(idleTimeout, readTimeout, writeTimeout time.Duration) echo.MiddlewareFunc {
	return requestLimitsWithUploadLease(idleTimeout, readTimeout, writeTimeout, acquireUploadLease)
}

// The injected lease function lets protocol/deadline tests run without Redis;
// production always uses acquireUploadLease.
func requestLimitsWithUploadLease(idleTimeout, readTimeout, writeTimeout time.Duration, acquire func(*http.Request, time.Duration) (func(), error)) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			select {
			case requestSlots <- struct{}{}:
				defer func() { <-requestSlots }()
			default:
				closeUnreadHTTP1(c)
				return echo.NewHTTPError(http.StatusServiceUnavailable, "Server is busy")
			}

			r := c.Request()
			upload := multipartFileUpload(r)
			started := time.Now()
			if upload {
				bodyBytes := r.ContentLength
				if bodyBytes > maxUploadBodyBytes {
					closeUnreadHTTP1(c)
					return echo.NewHTTPError(http.StatusRequestEntityTooLarge, "Request body too large")
				}
				leaseTTL := readTimeout
				if writeTimeout > leaseTTL {
					leaseTTL = writeTimeout
				}
				if leaseTTL <= 0 || leaseTTL > time.Duration(math.MaxInt64)-10*time.Minute || acquire == nil {
					closeUnreadHTTP1(c)
					return echo.NewHTTPError(http.StatusServiceUnavailable, "Upload admission is unavailable")
				}
				release, err := acquire(r, leaseTTL+10*time.Minute)
				if err != nil || release == nil {
					closeUnreadHTTP1(c)
					if errors.Is(err, ErrUploadLeaseBusy) {
						c.Response().Header().Set(echo.HeaderRetryAfter, "60")
						return echo.NewHTTPError(http.StatusTooManyRequests, "Another upload is in progress")
					}
					return echo.NewHTTPError(http.StatusServiceUnavailable, "Upload admission is unavailable")
				}
				defer release()
				select {
				case uploadSlots <- struct{}{}:
					defer func() { <-uploadSlots }()
				default:
					closeUnreadHTTP1(c)
					return echo.NewHTTPError(http.StatusServiceUnavailable, "Upload capacity is busy")
				}
				if bodyBytes < 0 {
					bodyBytes = maxUploadBodyBytes
				}
				// Remove only abandoned, lock-protected staging directories;
				// active transfers in this or another process retain their locks.
				if err := utils.CleanupStaleStagingDirs(utils.FILEFOLDER); err != nil {
					closeUnreadHTTP1(c)
					return echo.NewHTTPError(http.StatusInsufficientStorage, "Upload storage is unavailable")
				}
				// Reserve for more entries than the controller currently accepts.
				reservation, err := utils.ReserveEncryptedUploadStorage(utils.FILEFOLDER, bodyBytes, 1000)
				if err != nil {
					closeUnreadHTTP1(c)
					return echo.NewHTTPError(http.StatusInsufficientStorage, "Upload storage is unavailable")
				}
				defer func() {
					// CSRF can parse a multipart body before its handler runs.
					if r.MultipartForm != nil {
						if err := r.MultipartForm.RemoveAll(); err != nil {
							log.Error("Failed to remove multipart temporary files")
						}
					}
					reservation.Release()
				}()
			}

			response := c.Response()
			controller := http.NewResponseController(response.Writer)
			originalWriter := response.Writer
			response.Writer = &idleDeadlineWriter{ResponseWriter: originalWriter, controller: controller, timeout: idleTimeout, absolute: started.Add(writeTimeout)}
			if r.Body != nil && r.Body != http.NoBody {
				absolute := started.Add(readTimeout)
				if !upload && started.Add(maxSmallBodyTime).Before(absolute) {
					absolute = started.Add(maxSmallBodyTime)
				}
				limitedBody := &idleDeadlineBody{ReadCloser: r.Body, controller: controller, timeout: idleTimeout, absolute: absolute}
				if upload {
					// An idle timeout alone permits an attacker to send one byte
					// just before every deadline. Bound cumulative elapsed time as
					// well, without buffering the upload or shortening the absolute
					// transfer limit for clients meeting the minimum average rate.
					limitedBody.rateStart = time.Now()
					limitedBody.rateGrace = uploadRateGrace
					limitedBody.minRate = minUploadBytesPerSec
				}
				// Also bound any server-side drain after rejecting a body based on
				// Content-Length, before this middleware performs its first read.
				_ = controller.SetReadDeadline(limitedBody.deadline())
				r.Body = limitedBody
			}

			if !upload && r.Body != nil && r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
				if r.ContentLength > maxSmallRequestBytes {
					closeUnreadHTTP1(c)
					return echo.NewHTTPError(http.StatusRequestEntityTooLarge, "Request body too large")
				}
				body, err := io.ReadAll(io.LimitReader(r.Body, maxSmallRequestBytes+1))
				if err != nil {
					closeUnreadHTTP1(c)
					return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body")
				}
				if len(body) > maxSmallRequestBytes {
					closeUnreadHTTP1(c)
					return echo.NewHTTPError(http.StatusRequestEntityTooLarge, "Request body too large")
				}
				_ = r.Body.Close()
				r.Body = io.NopCloser(bytes.NewReader(body))
				r.ContentLength = int64(len(body))
			}
			return next(c)
		}
	}
}

type idleDeadlineBody struct {
	io.ReadCloser
	controller *http.ResponseController
	timeout    time.Duration
	absolute   time.Time
	rateStart  time.Time
	rateGrace  time.Duration
	minRate    int64
	bytesRead  int64
}

func (b *idleDeadlineBody) Read(p []byte) (int, error) {
	// A few test and embedding writers do not implement deadlines. The server's
	// absolute ReadTimeout remains a backstop in that case.
	_ = b.controller.SetReadDeadline(b.deadline())
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.bytesRead += int64(n)
	}
	if err == io.EOF {
		// Reading is finished. In particular, do not let a body deadline
		// expire during subsequent ZIP creation or response generation.
		_ = b.controller.SetReadDeadline(time.Time{})
	}
	return n, err
}

func (b *idleDeadlineBody) deadline() time.Time {
	deadline := time.Now().Add(b.timeout)
	if b.absolute.Before(deadline) {
		deadline = b.absolute
	}
	if b.minRate > 0 && !b.rateStart.IsZero() {
		// The request's body is separately bounded to approximately 1 GB,
		// so the multiplication remains within time.Duration's range.
		allowance := time.Duration(b.bytesRead * int64(time.Second) / b.minRate)
		rateDeadline := b.rateStart.Add(b.rateGrace + allowance)
		if rateDeadline.Before(deadline) {
			return rateDeadline
		}
	}
	return deadline
}

type idleDeadlineWriter struct {
	http.ResponseWriter
	controller *http.ResponseController
	timeout    time.Duration
	absolute   time.Time
}

func (w *idleDeadlineWriter) deadline() time.Time {
	deadline := time.Now().Add(w.timeout)
	if w.absolute.Before(deadline) {
		return w.absolute
	}
	return deadline
}

func (w *idleDeadlineWriter) WriteHeader(status int) {
	_ = w.controller.SetWriteDeadline(w.deadline())
	w.ResponseWriter.WriteHeader(status)
}

func (w *idleDeadlineWriter) Write(p []byte) (int, error) {
	_ = w.controller.SetWriteDeadline(w.deadline())
	return w.ResponseWriter.Write(p)
}

func (w *idleDeadlineWriter) Flush() {
	_ = w.controller.SetWriteDeadline(w.deadline())
	_ = w.controller.Flush()
}

func (w *idleDeadlineWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
