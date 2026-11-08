package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"bouclier/internal/api/middleware"
	"bouclier/internal/config"
)

func testHTTPConfig() config.HTTPServerConfig {
	return config.Default().HTTPServer
}

func TestNewServer(t *testing.T) {
	cfg := testHTTPConfig()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := NewServer(cfg, logger)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	if server.Addr != "127.0.0.1:8081" {
		t.Errorf("Addr = %q, want 127.0.0.1:8081", server.Addr)
	}
	if server.ReadHeaderTimeout != cfg.ReadHeaderTimeout ||
		server.ReadTimeout != cfg.ReadTimeout ||
		server.WriteTimeout != cfg.WriteTimeout ||
		server.IdleTimeout != cfg.IdleTimeout {
		t.Errorf("server timeouts do not match configuration: %+v", server)
	}
	if server.Handler == nil {
		t.Fatal("NewServer() returned nil Handler")
	}
}

func TestNewServerRejectsInvalidConfiguration(t *testing.T) {
	cfg := testHTTPConfig()
	cfg.Host = "0.0.0.0"
	if _, err := NewServer(cfg, nil); err == nil {
		t.Fatal("NewServer() succeeded with a wildcard host")
	}
}

func TestInitialRoutes(t *testing.T) {
	server, err := NewServer(testHTTPConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		path string
		want any
	}{
		{"/health", map[string]string{"status": "ok", "service": "bouclier-api"}},
		{"/ready", map[string]string{"status": "ready"}},
		{"/api/v1", map[string]string{"name": "Bouclier API", "version": "v1"}},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			server.Handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, tt.path, nil))
			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
			}
			var got map[string]string
			if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
				t.Fatalf("response is not JSON: %v", err)
			}
			expected, err := json.Marshal(tt.want)
			if err != nil {
				t.Fatal(err)
			}
			var want map[string]string
			if err := json.Unmarshal(expected, &want); err != nil {
				t.Fatal(err)
			}
			if len(got) != len(want) {
				t.Fatalf("response fields = %#v, want %#v", got, want)
			}
			for key, value := range want {
				if got[key] != value {
					t.Errorf("%s = %q, want %q", key, got[key], value)
				}
			}
			if recorder.Header().Get("Content-Type") != "application/json; charset=utf-8" {
				t.Errorf("Content-Type = %q", recorder.Header().Get("Content-Type"))
			}
		})
	}
}

func TestRoutesReturnJSONErrors(t *testing.T) {
	server, err := NewServer(testHTTPConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		method    string
		path      string
		status    int
		errorCode string
	}{
		{"unknown path", http.MethodGet, "/missing", http.StatusNotFound, "not_found"},
		{"wrong method", http.MethodPost, "/health", http.StatusMethodNotAllowed, "method_not_allowed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			server.Handler.ServeHTTP(recorder, httptest.NewRequest(tt.method, tt.path, nil))
			if recorder.Code != tt.status {
				t.Fatalf("status = %d, want %d", recorder.Code, tt.status)
			}
			if !strings.Contains(recorder.Header().Get("Content-Type"), "application/json") {
				t.Fatalf("Content-Type = %q, want JSON", recorder.Header().Get("Content-Type"))
			}
			if tt.method == http.MethodPost && recorder.Header().Get("Allow") != http.MethodGet {
				t.Errorf("Allow = %q, want GET", recorder.Header().Get("Allow"))
			}
			var payload struct {
				Error struct {
					Code      string `json:"code"`
					RequestID string `json:"request_id"`
				} `json:"error"`
			}
			if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
				t.Fatalf("error response is not JSON: %v", err)
			}
			if payload.Error.Code != tt.errorCode {
				t.Errorf("error code = %q, want %q", payload.Error.Code, tt.errorCode)
			}
			if payload.Error.RequestID != recorder.Header().Get(middleware.RequestIDHeader) {
				t.Errorf("error request ID = %q, response header = %q", payload.Error.RequestID, recorder.Header().Get(middleware.RequestIDHeader))
			}
		})
	}
}

func TestServeGracefulShutdown(t *testing.T) {
	server, err := NewServer(testHTTPConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, server, listener, nil) }()

	client := &http.Client{Timeout: 2 * time.Second}
	url := "http://" + listener.Addr().String() + "/health"
	deadline := time.Now().Add(2 * time.Second)
	for {
		response, requestErr := client.Get(url)
		if requestErr == nil {
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if response.StatusCode != http.StatusOK {
				cancel()
				t.Fatalf("health status = %d, want 200", response.StatusCode)
			}
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("server did not start: %v", requestErr)
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve() after cancellation error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve() did not shut down after context cancellation")
	}
}

func TestServeRejectsMissingInputs(t *testing.T) {
	if err := Serve(context.Background(), nil, nil, nil); err == nil {
		t.Fatal("Serve() accepted a nil server")
	}
	server, err := NewServer(testHTTPConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := Serve(context.Background(), server, nil, nil); err == nil {
		t.Fatal("Serve() accepted a nil listener")
	}
}

func TestServeRejectsNonLoopbackListener(t *testing.T) {
	server, err := NewServer(testHTTPConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	listener := testListener{addr: &net.TCPAddr{IP: net.IPv4zero, Port: 8081}}
	if err := Serve(context.Background(), server, listener, nil); err == nil {
		t.Fatal("Serve() accepted a non-loopback listener")
	}
}

func TestServeReturnsUnexpectedListenerError(t *testing.T) {
	server, err := NewServer(testHTTPConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := Serve(context.Background(), server, listener, nil); err == nil {
		t.Fatal("Serve() succeeded with a closed listener")
	}
}

type testListener struct {
	addr net.Addr
}

func (l testListener) Accept() (net.Conn, error) {
	return nil, net.ErrClosed
}

func (l testListener) Close() error {
	return nil
}

func (l testListener) Addr() net.Addr {
	return l.addr
}
