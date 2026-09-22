package handlers

import (
	"net/http"
	"strconv"
	"time"

	"github.com/logmonitor/gateway/internal/auth"
	"github.com/logmonitor/gateway/internal/httpx"
	"github.com/logmonitor/gateway/internal/store"
)

const defaultWindowDays = 30

// scopeFrom builds the tenancy filter for a dashboard request.
//
// The default is always the caller's own data. Widening to the organization
// is opt-in via ?scope=org AND requires an admin -- a member asking for it is
// refused rather than silently narrowed, so a UI bug surfaces as an error
// instead of quietly showing the wrong thing.
func scopeFrom(r *http.Request, caller *store.User) (store.Scope, error) {
	now := time.Now().UTC()
	sc := store.Scope{
		OrgID: caller.OrgID,
		From:  now.AddDate(0, 0, -defaultWindowDays),
		To:    now.Add(time.Minute),
	}

	if v := r.URL.Query().Get("from"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return sc, errBadRequest("from must be an RFC3339 timestamp")
		}
		sc.From = t
	}
	if v := r.URL.Query().Get("to"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return sc, errBadRequest("to must be an RFC3339 timestamp")
		}
		sc.To = t
	}
	if sc.To.Before(sc.From) {
		return sc, errBadRequest("to is before from")
	}

	if r.URL.Query().Get("scope") == "org" {
		if !caller.Role.IsAdmin() {
			return sc, errForbidden("Only an administrator can view organization-wide figures")
		}
		return sc, nil // UserID stays nil => org-wide
	}
	id := caller.ID
	sc.UserID = &id
	return sc, nil
}

type statusError struct {
	status int
	msg    string
}

func (e statusError) Error() string { return e.msg }
func errBadRequest(m string) error  { return statusError{http.StatusBadRequest, m} }
func errForbidden(m string) error   { return statusError{http.StatusForbidden, m} }
func failWith(w http.ResponseWriter, err error) {
	if se, ok := err.(statusError); ok {
		httpx.Fail(w, se.status, se.msg)
		return
	}
	httpx.Fail(w, http.StatusInternalServerError, "Something went wrong")
}

func (a *API) dashboardSummary(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserFrom(r.Context())
	sc, err := scopeFrom(r, caller)
	if err != nil {
		failWith(w, err)
		return
	}

	summary, err := a.Store.DashboardSummary(r.Context(), sc)
	if err != nil {
		a.Log.Error("summary failed", "event", "dashboard.summary_failed", "err", err)
		httpx.Fail(w, http.StatusInternalServerError, "Could not load the summary")
		return
	}
	findings, err := a.Store.FindingBreakdown(r.Context(), sc)
	if err != nil {
		a.Log.Error("findings failed", "event", "dashboard.findings_failed", "err", err)
		httpx.Fail(w, http.StatusInternalServerError, "Could not load findings")
		return
	}

	httpx.JSON(w, http.StatusOK, map[string]any{
		"summary":  summary,
		"findings": findings,
		"scope":    scopeLabel(sc),
		"from":     sc.From, "to": sc.To,
	})
}

func scopeLabel(sc store.Scope) string {
	if sc.UserID == nil {
		return "org"
	}
	return "self"
}

func (a *API) dashboardSeries(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserFrom(r.Context())
	sc, err := scopeFrom(r, caller)
	if err != nil {
		failWith(w, err)
		return
	}
	points, err := a.Store.DashboardSeries(r.Context(), sc, r.URL.Query().Get("grain"))
	if err != nil {
		a.Log.Error("series failed", "event", "dashboard.series_failed", "err", err)
		httpx.Fail(w, http.StatusInternalServerError, "Could not load the series")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"points": points, "scope": scopeLabel(sc)})
}

func (a *API) dashboardTop(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserFrom(r.Context())
	sc, err := scopeFrom(r, caller)
	if err != nil {
		failWith(w, err)
		return
	}
	dimension := r.URL.Query().Get("dimension")
	if dimension == "" {
		dimension = "host"
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))

	rows, err := a.Store.DashboardTop(r.Context(), sc, dimension, limit)
	if err != nil {
		httpx.Fail(w, http.StatusBadRequest, "dimension must be one of: host, url, user, ip, category")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"rows": rows, "dimension": dimension})
}

// listAudit exposes the organization's audit trail. Admin-only: it names who
// looked at what, which is itself sensitive.
func (a *API) listAudit(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserFrom(r.Context())
	if !caller.Role.IsAdmin() {
		httpx.Fail(w, http.StatusForbidden, "Only an administrator can view the audit log")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	entries, err := a.Store.ListAudit(r.Context(), caller.OrgID, limit)
	if err != nil {
		a.Log.Error("audit list failed", "event", "audit.list_failed", "err", err)
		httpx.Fail(w, http.StatusInternalServerError, "Could not load the audit log")
		return
	}
	httpx.JSON(w, http.StatusOK, entries)
}

// statusCodes serves the response-code breakdown.
func (a *API) statusCodes(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserFrom(r.Context())
	sc, err := scopeFrom(r, caller)
	if err != nil {
		failWith(w, err)
		return
	}
	rows, err := a.Store.StatusCodes(r.Context(), sc)
	if err != nil {
		a.Log.Error("status breakdown failed", "event", "dashboard.status_failed", "err", err)
		httpx.Fail(w, http.StatusInternalServerError, "Could not load the status breakdown")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"codes": rows})
}

// actionPlan serves findings ordered by what to do first.
func (a *API) actionPlan(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserFrom(r.Context())
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))

	items, err := a.Store.ActionPlan(r.Context(), caller, limit)
	if err != nil {
		a.Log.Error("action plan failed", "event", "dashboard.plan_failed", "err", err)
		httpx.Fail(w, http.StatusInternalServerError, "Could not load the action plan")
		return
	}

	httpx.JSON(w, http.StatusOK, map[string]any{"items": items})
}
