// Package handlers wires HTTP routes to the store and the authz resolver.
package handlers

import (
	"crypto/subtle"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strings"

	"github.com/google/uuid"

	"github.com/logmonitor/gateway/internal/auth"
	"github.com/logmonitor/gateway/internal/authz"
	"github.com/logmonitor/gateway/internal/blob"
	"github.com/logmonitor/gateway/internal/config"
	"github.com/logmonitor/gateway/internal/httpx"
	"github.com/logmonitor/gateway/internal/queue"
	"github.com/logmonitor/gateway/internal/ratelimit"
	"github.com/logmonitor/gateway/internal/store"
)

type API struct {
	Cfg     *config.Config
	Store   *store.Store
	Auth    *auth.Manager
	Authz   *authz.Resolver
	Limiter *ratelimit.Limiter
	Blob    blob.Store
	Queue   *queue.Publisher
	Log     *slog.Logger
}

// audit writes one record and never fails the request that produced it -- but
// a failure is logged, because an audit trail nobody notices is broken is not
// an audit trail. (authz.Require is the exception: there the record IS the
// justification, so a failed write denies the access.)
func (a *API) audit(r *http.Request, orgID uuid.UUID, actor *uuid.UUID,
	action, resourceType string, resourceID *uuid.UUID, detail map[string]any) {
	if err := a.Store.Audit(r.Context(), orgID, actor, action, resourceType, resourceID, detail); err != nil {
		a.Log.Error("audit write failed", "event", "audit.failed", "action", action, "err", err)
	}
}

// clientIP prefers the proxy's forwarded address, since every request arrives
// through the Next.js proxy and RemoteAddr would otherwise be one constant
// value for the whole world -- which would make IP rate limiting a global
// counter rather than a per-client one.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if rip := r.Header.Get("X-Real-IP"); rip != "" {
		return strings.TrimSpace(rip)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// Routes returns the mux. Go 1.22 patterns carry the method and path
// parameters, so no third-party router is needed.
func (a *API) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	req := a.Auth.Require

	mux.HandleFunc("GET /api/health", a.health)

	mux.HandleFunc("POST /api/auth/register", a.register)
	mux.HandleFunc("POST /api/auth/login", a.login)
	mux.HandleFunc("POST /api/auth/logout", a.logout)
	mux.HandleFunc("GET /api/auth/me", req(a.me))

	// Step two of login: authenticated by the short-lived MFA cookie only.
	mux.HandleFunc("POST /api/auth/mfa/verify", a.verifyMFA)
	mux.HandleFunc("POST /api/auth/mfa/enroll", req(a.enrollMFA))
	mux.HandleFunc("POST /api/auth/mfa/activate", req(a.activateMFA))
	mux.HandleFunc("POST /api/auth/mfa/disable", req(a.disableMFA))

	mux.HandleFunc("GET /api/org/users", req(a.listOrgUsers))
	mux.HandleFunc("POST /api/org/invite", req(a.inviteMember))
	mux.HandleFunc("POST /api/org/users/{id}/mfa/reset", req(a.resetMemberMFA))
	mux.HandleFunc("POST /api/org/mfa-policy", req(a.setOrgMFAPolicy))

	mux.HandleFunc("GET /api/grants", req(a.listGrants))
	mux.HandleFunc("POST /api/grants", req(a.createGrant))
	mux.HandleFunc("DELETE /api/grants/{id}", req(a.deleteGrant))

	mux.HandleFunc("GET /api/uploads", req(a.listUploads))
	mux.HandleFunc("POST /api/uploads", req(a.createUpload))
	mux.HandleFunc("POST /api/uploads/{id}/analyze", req(a.startAnalysis))
	mux.HandleFunc("GET /api/analyses/{id}", req(a.getAnalysis))

	mux.HandleFunc("GET /api/dashboard/summary", req(a.dashboardSummary))
	mux.HandleFunc("GET /api/dashboard/series", req(a.dashboardSeries))
	mux.HandleFunc("GET /api/dashboard/top", req(a.dashboardTop))
	mux.HandleFunc("GET /api/dashboard/status", req(a.statusCodes))
	mux.HandleFunc("GET /api/dashboard/actions", req(a.actionPlan))
	mux.HandleFunc("GET /api/audit", req(a.listAudit))
	mux.HandleFunc("GET /api/search", req(a.search))

	mux.HandleFunc("GET /api/metrics", a.metrics)
	return mux
}

func (a *API) health(w http.ResponseWriter, r *http.Request) {
	httpx.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// metrics is operator-only, behind a static token rather than a user session.
//
// In v1 this endpoint was gated on any logged-in user's cookie but returned
// process-wide counters -- upload volumes and bytes across every tenant. Under
// a model where a user may only see their own data, that was a leak. Per-user
// and per-org figures now come from the dashboard endpoints instead.
func (a *API) metrics(w http.ResponseWriter, r *http.Request) {
	// X-Metrics-Token rather than `Authorization: Bearer`.
	//
	// The edge Basic Auth gate already occupies the Authorization header, and
	// a request can only carry one. Sharing that header meant the operator
	// token could never reach this handler whenever the gate was enabled --
	// found by running the two together rather than in isolation.
	token := r.Header.Get("X-Metrics-Token")
	if token == "" {
		token = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	}
	if a.Cfg.MetricsToken == "" ||
		subtle.ConstantTimeCompare([]byte(token), []byte(a.Cfg.MetricsToken)) != 1 {
		httpx.Fail(w, http.StatusUnauthorized, "Not authenticated")
		return
	}
	httpx.JSON(w, http.StatusOK, a.processMetrics())
}

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

func slugify(s string) string {
	return strings.Trim(slugRe.ReplaceAllString(strings.ToLower(s), "-"), "-")
}
