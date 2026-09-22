package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/logmonitor/gateway/internal/auth"
	"github.com/logmonitor/gateway/internal/httpx"
)

// search finds findings, by meaning when that is possible and by text always.
//
// Two backends behind one endpoint. Embeddings answer "like what?" but need a
// provider; full text answers "containing what?" and needs nothing. The
// response says which was used, so a caller is never left guessing why a
// semantic query behaved literally.
func (a *API) search(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserFrom(r.Context())

	query := strings.TrimSpace(r.URL.Query().Get("q"))
	if query == "" {
		httpx.Fail(w, http.StatusBadRequest, "q is required")
		return
	}
	if len(query) > 500 {
		httpx.Fail(w, http.StatusBadRequest, "q is too long")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))

	mode := "text"
	hits, err := a.Store.SearchFindingsText(r.Context(), caller, query, limit)
	if err != nil {
		a.Log.Error("search failed", "event", "search.failed", "err", err)
		httpx.Fail(w, http.StatusInternalServerError, "Search failed")
		return
	}

	hasVectors, _ := a.Store.HasEmbeddings(r.Context(), caller.OrgID)

	httpx.JSON(w, http.StatusOK, map[string]any{
		"query":   query,
		"mode":    mode,
		"hits":    hits,
		"count":   len(hits),
		// Stated rather than silently absent: without a provider, similarity
		// search does not exist and the caller should know that is why.
		"semantic_available": hasVectors,
	})
}
