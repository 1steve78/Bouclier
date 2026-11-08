package api

import (
	"encoding/json"
	"net/http"

	"bouclier/internal/api/contract"
	"bouclier/internal/api/middleware"
)

func registerRoutes(mux *http.ServeMux, scanHandler ...http.Handler) {
	registerGET(mux, "/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, contract.HealthResponse{Status: "ok", Service: "bouclier-api"})
	})
	registerGET(mux, "/ready", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, contract.ReadinessResponse{Status: "ready"})
	})
	registerGET(mux, "/api/v1", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, contract.MetadataResponse{Name: "Bouclier API", Version: "v1"})
	})
	if len(scanHandler) > 0 && scanHandler[0] != nil {
		mux.Handle("/api/v1/scans", scanHandler[0])
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		middleware.WriteJSONError(w, http.StatusNotFound, contract.ErrorCodeNotFound, "The requested resource was not found.")
	})
}

func registerGET(mux *http.ServeMux, path string, handler http.HandlerFunc) {
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			middleware.WriteJSONError(w, http.StatusMethodNotAllowed, contract.ErrorCodeMethodNotAllowed, "The requested method is not allowed.")
			return
		}
		handler(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
