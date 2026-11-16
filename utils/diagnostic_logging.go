package utils

import (
	"io"
	stdlog "log"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// NewHTTPDiagnosticLogger routes net/http diagnostics through the application
// logger. net/http may include attacker-controlled data in its diagnostic
// strings, so the bridge emits recognised categories, not raw messages.
// Keeping the underlying Logrus logger independent from the standard logger
// also avoids recursion when the standard logger is configured elsewhere.
func NewHTTPDiagnosticLogger(logger *logrus.Logger) *stdlog.Logger {
	return stdlog.New(diagnosticWriter{logger: logger, component: "http.server"}, "", 0)
}

// NewStandardDiagnosticWriter routes the Go standard logger through Logrus.
// Standard log calls carry no severity; unclassified entries are warnings.
// Output must not point back at the standard logger, or it would recurse.
func NewStandardDiagnosticWriter(logger *logrus.Logger) io.Writer {
	return diagnosticWriter{logger: logger, component: "go.standard"}
}

type diagnosticWriter struct {
	logger    *logrus.Logger
	component string
}

func (w diagnosticWriter) Write(p []byte) (int, error) {
	// A panic value or error may include input controlled by the peer. Bound
	// inspection and allocation without copying arbitrary text into the log.
	const maxDiagnosticBytes = 128 << 10
	input := p
	truncated := len(input) > maxDiagnosticBytes
	if truncated {
		input = input[:maxDiagnosticBytes]
	}
	message := strings.TrimSpace(string(input))
	entry := w.logger.WithField("component", w.component)
	if truncated {
		entry = entry.WithField("diagnostic_truncated", true)
	}
	switch {
	case message == "timeout waiting for PING response":
		entry.WithField("event", "http2.ping_timeout").Warn("HTTP/2 PING response timed out")
	case strings.HasPrefix(message, "timeout waiting for SETTINGS frames from "):
		peer := strings.TrimPrefix(message, "timeout waiting for SETTINGS frames from ")
		entry = diagnosticPeerAddress(entry, peer)
		entry.WithField("event", "http2.settings_timeout").Warn("HTTP/2 SETTINGS frames timed out")
	case strings.HasPrefix(message, "http2: server: error reading preface from client "):
		details := strings.TrimPrefix(message, "http2: server: error reading preface from client ")
		entry = diagnosticPeer(entry, details)
		entry.WithFields(logrus.Fields{"event": "http2.preface_failed", "reason_class": http2DiagnosticClass(diagnosticReason(details))}).Warn("HTTP/2 client preface could not be read")
	case strings.HasPrefix(message, "http2: server connection error from "):
		details := strings.TrimPrefix(message, "http2: server connection error from ")
		entry = diagnosticPeer(entry, details)
		entry.WithFields(logrus.Fields{"event": "http2.connection_error", "reason_class": http2DiagnosticClass(diagnosticReason(details))}).Warn("HTTP/2 connection error")
	case strings.HasPrefix(message, "http2: server closing client connection: "):
		details := strings.TrimPrefix(message, "http2: server closing client connection: ")
		entry.WithFields(logrus.Fields{"event": "http2.connection_closed", "reason_class": http2DiagnosticClass(details)}).Warn("HTTP/2 client connection closed after an error")
	case strings.HasPrefix(message, "http2: received GOAWAY ") && strings.HasSuffix(message, ", starting graceful shutdown"):
		entry.WithField("event", "http2.peer_goaway").Warn("HTTP/2 peer sent GOAWAY; connection is closing")
	case strings.HasPrefix(message, "http: superfluous response.WriteHeader call from "):
		entry.WithField("event", "http.response_header_repeated").Warn("HTTP response headers were written more than once")
	case strings.HasPrefix(message, "http: response.WriteHeader on hijacked connection from "):
		entry.WithField("event", "http.response_header_after_hijack").Warn("HTTP response headers were written after connection hijack")
	case strings.HasPrefix(message, "http: response.Write on hijacked connection from "):
		entry.WithField("event", "http.response_write_after_hijack").Warn("HTTP response was written after connection hijack")
	case strings.HasPrefix(message, "http: invalid Content-Length of "):
		entry.WithField("event", "http.response_invalid_content_length").Warn("HTTP response had an invalid Content-Length")
	case strings.HasPrefix(message, "http: WriteHeader called with both Transfer-Encoding of ") && strings.Contains(message, " and a Content-Length of "):
		entry.WithField("event", "http.response_conflicting_framing").Warn("HTTP response declared conflicting message framing")
	case strings.HasPrefix(message, "ignoring invalid trailer "):
		entry.WithField("event", "http2.invalid_trailer").Warn("HTTP/2 ignored an invalid response trailer")
	case strings.HasPrefix(message, "http: TLS handshake error from "):
		details := strings.TrimPrefix(message, "http: TLS handshake error from ")
		entry = diagnosticPeer(entry, details)
		entry.WithFields(logrus.Fields{"event": "tls.handshake_failed", "reason_class": tlsDiagnosticClass(details)}).Warn("TLS handshake failed")
	case strings.HasPrefix(message, "http: Accept error: "):
		details := strings.TrimPrefix(message, "http: Accept error: ")
		entry = entry.WithFields(logrus.Fields{"event": "http.accept_failed", "reason_class": acceptDiagnosticClass(details)})
		if _, delayText, ok := strings.Cut(details, "; retrying in "); ok {
			if delay, err := time.ParseDuration(delayText); err == nil && delay > 0 && delay <= time.Minute {
				entry = entry.WithField("retry_delay", delay.String())
			}
		}
		entry.Error("HTTP server could not accept a connection; retrying")
	case strings.HasPrefix(message, "http2: panic serving "):
		details := strings.TrimPrefix(message, "http2: panic serving ")
		entry = diagnosticPeer(entry, details)
		if !truncated {
			entry = diagnosticPanicLocation(entry, details)
		}
		entry.WithFields(logrus.Fields{"event": "http2.handler_panic", "stack_trace_present": strings.Contains(details, "\n")}).Error("HTTP/2 handler panicked")
	case strings.HasPrefix(message, "http: panic serving "):
		details := strings.TrimPrefix(message, "http: panic serving ")
		entry = diagnosticPeer(entry, details)
		if !truncated {
			entry = diagnosticPanicLocation(entry, details)
		}
		entry.WithFields(logrus.Fields{"event": "http.handler_panic", "stack_trace_present": strings.Contains(details, "\n")}).Error("HTTP handler panicked")
	default:
		if w.component == "go.standard" {
			entry.WithField("event", "go.standard_diagnostic").Warn("Go standard logger reported a diagnostic")
		} else {
			entry.WithField("event", "http.server_diagnostic").Error("HTTP server reported a diagnostic")
		}
	}
	return len(p), nil
}

// diagnosticReason discards the untrusted peer address and returns only the
// diagnostic suffix for classification; the suffix itself is never logged.
func diagnosticReason(details string) string {
	_, reason, ok := strings.Cut(details, ": ")
	if !ok {
		return ""
	}
	return reason
}

// http2DiagnosticClass returns a small fixed vocabulary without exposing
// protocol bytes, request content, private paths, or arbitrary error text.
func http2DiagnosticClass(reason string) string {
	switch {
	case reason == "EOF":
		return "peer_closed"
	case reason == "unexpected EOF":
		return "unexpected_eof"
	case strings.HasSuffix(reason, ": i/o timeout") || reason == "i/o timeout":
		return "timeout"
	case strings.HasSuffix(reason, ": connection reset by peer") || reason == "connection reset by peer":
		return "connection_reset"
	case strings.HasSuffix(reason, ": broken pipe") || reason == "broken pipe":
		return "broken_pipe"
	default:
		return "other"
	}
}

// acceptDiagnosticClass is deliberately limited to broad known error families;
// the originating error can contain arbitrary listener addresses or text.
func acceptDiagnosticClass(details string) string {
	switch {
	case strings.Contains(details, "too many open files"):
		return "file_descriptor_exhaustion"
	case strings.Contains(details, "cannot allocate memory"):
		return "memory_exhaustion"
	case strings.Contains(details, "no buffer space available"):
		return "buffer_exhaustion"
	case strings.Contains(details, "connection aborted"):
		return "connection_aborted"
	case strings.Contains(details, "connection reset by peer"):
		return "connection_reset"
	case strings.Contains(details, "network is down"), strings.Contains(details, "network is unreachable"):
		return "network_unavailable"
	case strings.Contains(details, "interrupted system call"):
		return "interrupted"
	default:
		return "other"
	}
}

// tlsDiagnosticClass keeps the broad cause useful without copying arbitrary
// error text supplied by a peer or exposing certificate contents.
func tlsDiagnosticClass(details string) string {
	_, reason, ok := strings.Cut(details, ": ")
	if !ok {
		return "other"
	}
	switch {
	case reason == "EOF" || reason == "unexpected EOF":
		return "peer_closed"
	case strings.HasSuffix(reason, "i/o timeout"):
		return "timeout"
	case strings.HasPrefix(reason, "tls: client offered only unsupported versions"):
		return "protocol_version"
	case strings.HasPrefix(reason, "remote error: tls: bad certificate"), strings.HasPrefix(reason, "tls: bad certificate"):
		return "certificate"
	default:
		return "other"
	}
}

// diagnosticPanicLocation extracts the first static project function from the
// runtime-generated stack. Panic values are untrusted and may contain forged
// newlines; use the last goroutine header, which follows the panic value.
// Stack arguments, source paths and the panic value are never copied.
func diagnosticPanicLocation(entry *logrus.Entry, details string) *logrus.Entry {
	stackStart := strings.LastIndex(details, "\ngoroutine ")
	if stackStart < 0 {
		return entry
	}
	for _, line := range strings.Split(details[stackStart+1:], "\n") {
		if !strings.HasPrefix(line, "github.com/jeanphilippe-mh/Okuru/") {
			continue
		}
		end := strings.LastIndexByte(line, '(')
		if end <= 0 || end > 256 {
			continue
		}
		function := line[:end]
		valid := true
		for _, r := range function {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("/._-*()", r)) {
				valid = false
				break
			}
		}
		if valid {
			return entry.WithField("panic_function", function)
		}
	}
	return entry
}

// diagnosticPeer extracts only a canonical network address, never the error
// text, panic value, HTTP path, port or arbitrary suffix from the diagnostic.
func diagnosticPeer(entry *logrus.Entry, details string) *logrus.Entry {
	peer, _, ok := strings.Cut(details, ": ")
	if !ok {
		return entry
	}
	return diagnosticPeerAddress(entry, peer)
}

// diagnosticPeerAddress accepts only a canonical IP and numeric port from a
// known diagnostic format, not a raw peer-controlled string.
func diagnosticPeerAddress(entry *logrus.Entry, peer string) *logrus.Entry {
	host, port, err := net.SplitHostPort(peer)
	if err != nil {
		return entry
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return entry
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" || ip.IsUnspecified() {
		return entry
	}
	return entry.WithField("peer_ip", ip.Unmap().String())
}
