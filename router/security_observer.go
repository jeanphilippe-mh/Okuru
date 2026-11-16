package router

import (
	"math"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v5"
	log "github.com/sirupsen/logrus"
)

// These are observations, not proof that a client is malicious. Counts are
// local to a worker and cover only requests that reach this application.
// Fixed windows and bounded state prevent an attacker from growing the map.
const (
	securityObservationWindow = 10 * time.Second
	securityAlertInterval     = 30 * time.Second
	securityPerSourceLimit    = 100
	securityGlobalLimit       = 1000
	securityMaxSources        = 2048
)

type securityGate struct {
	next       time.Time
	suppressed uint32
}

type securityObservation struct {
	probe      bool
	probeClass string
	sourceHigh bool
	globalHigh bool
	suppressed [3]uint32
}

type securityObserver struct {
	mu      sync.Mutex
	start   time.Time
	total   uint32
	sources map[string]uint16
	gates   [3]securityGate
}

func newSecurityObserver() *securityObserver {
	return &securityObserver{sources: make(map[string]uint16)}
}

// All recognised strings are application-independent and fixed. Never return
// the actual request path, query string, access key or a caller-supplied value.
func securityProbeClass(path string) string {
	if len(path) > 256 {
		return ""
	}
	switch strings.ToLower(path) {
	case "/.env", "/.env.local", "/.env.production":
		return "environment_file"
	case "/.git/config", "/.git/head":
		return "git_metadata"
	case "/wp-login.php", "/wp-admin", "/wp-admin/":
		return "wordpress_endpoint"
	case "/phpmyadmin", "/phpmyadmin/":
		return "database_admin_endpoint"
	default:
		return ""
	}
}

// Security alerts are globally limited per kind. The number suppressed since
// the previous alert is carried on the next emitted alert, capped safely.
func (s *securityObserver) allowAlertLocked(kind int, now time.Time) (bool, uint32) {
	gate := &s.gates[kind]
	if !gate.next.IsZero() && now.Before(gate.next) {
		if gate.suppressed < math.MaxUint32 {
			gate.suppressed++
		}
		return false, 0
	}
	suppressed := gate.suppressed
	gate.suppressed = 0
	gate.next = now.Add(securityAlertInterval)
	return true, suppressed
}

func (s *securityObserver) observe(now time.Time, source, probe string) securityObservation {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.start.IsZero() || now.Before(s.start) || now.Sub(s.start) >= securityObservationWindow {
		s.start = now
		s.total = 0
		clear(s.sources)
	}
	var result securityObservation
	if probe != "" {
		result.probe, result.suppressed[0] = s.allowAlertLocked(0, now)
		result.probeClass = probe
	}
	if s.total < securityGlobalLimit {
		s.total++
		if s.total == securityGlobalLimit {
			result.globalHigh, result.suppressed[2] = s.allowAlertLocked(2, now)
		}
	}
	if source != "" {
		count, exists := s.sources[source]
		if exists || len(s.sources) < securityMaxSources {
			if count < securityPerSourceLimit {
				count++
				s.sources[source] = count
				if count == securityPerSourceLimit {
					result.sourceHigh, result.suppressed[1] = s.allowAlertLocked(1, now)
				}
			}
		}
	}
	return result
}

// Only attribute an alert when the existing trusted-proxy resolver produced a
// public address. Group IPv6 privacy addresses by /64 for the rolling budget.
func securitySource(r *http.Request) string {
	address, err := utils.ResolveClientAddress(r)
	if err != nil || address.ClientIP == "" || !utils.IsPublicClientIP(address.ClientIP) {
		return ""
	}
	ip, err := netip.ParseAddr(address.ClientIP)
	if err != nil {
		return ""
	}
	ip = ip.Unmap()
	if ip.Is6() {
		return netip.PrefixFrom(ip, 64).Masked().String()
	}
	return ip.String()
}

// Shared between routers in one process so constructing multiple routers does
// not multiply the memory bound or the alert budget.
var processSecurityObserver = newSecurityObserver()

func securityObservations(observer *securityObserver) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			r := c.Request()
			source := securitySource(r)
			probe := ""
			if r != nil && r.URL != nil {
				probe = securityProbeClass(r.URL.Path)
			}
			observed := observer.observe(time.Now(), source, probe)
			// Do not misidentify a local/shared proxy as a visitor. Request ID
			// still makes an unattributed probe correlatable to its HTTP log.
			alertContext := c
			if source == "" {
				alertContext = nil
			}
			if observed.probe {
				fields := log.Fields{"signal": observed.probeClass, "suppressed": observed.suppressed[0]}
				if alertContext == nil {
					fields["trigger_request_id"] = utils.AuditRequestID(c)
				}
				utils.SecurityAlert(alertContext, "security.suspicious_probe", "A request matched a sensitive endpoint probe pattern", fields)
			}
			if observed.sourceHigh {
				fields := log.Fields{"requests": securityPerSourceLimit, "window_seconds": int(securityObservationWindow.Seconds()), "suppressed": observed.suppressed[1], "source_scope": "ipv4_or_ipv6_64"}
				utils.SecurityAlert(alertContext, "security.high_source_rate", "High request rate observed for a client address or prefix", fields)
			}
			if observed.globalHigh {
				fields := log.Fields{"requests": securityGlobalLimit, "window_seconds": int(securityObservationWindow.Seconds()), "suppressed": observed.suppressed[2], "trigger_request_id": utils.AuditRequestID(c)}
				utils.SecurityAlert(nil, "security.high_request_rate", "High request rate observed by this server process", fields)
			}
			return next(c)
		}
	}
}
