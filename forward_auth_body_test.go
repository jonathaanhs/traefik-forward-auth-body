package traefik_forward_auth_body

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestForwardAuthBody_SuccessfulAuth(t *testing.T) {
	// Create a mock forward auth server
	mockAuthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify method and content type
		if r.Method != http.MethodPost {
			t.Errorf("Expected method POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
		}

		// Read and verify the forwarded request body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("Failed to read forwarded request body: %v", err)
		}
		defer r.Body.Close()

		var requestBody map[string]interface{}
		if err := json.Unmarshal(body, &requestBody); err != nil {
			t.Fatalf("Failed to parse forwarded request body: %v", err)
		}

		if requestBody["test"] != "data" {
			t.Errorf("Expected forwarded body to contain test:data, got %v", requestBody)
		}

		// Set auth response headers
		w.Header().Set("X-Auth-User", "testuser")
		w.Header().Set("X-Custom-Header", "custom-value")
		if _, err := w.Write([]byte("OK")); err != nil {
			t.Fatalf("Failed to write response: %v", err)
		}
	}))
	defer mockAuthServer.Close()

	cfg := &Config{
		ForwardAuthURL:        mockAuthServer.URL,
		PreserveRequestMethod: true,
	}

	nextHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// Verify auth headers were forwarded
		if req.Header.Get("X-Auth-User") != "testuser" {
			t.Error("X-Auth-User header was not forwarded")
		}
		if req.Header.Get("X-Custom-Header") != "custom-value" {
			t.Error("X-Custom-Header was not forwarded")
		}

		// Verify request body is intact
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatalf("Failed to read request body in next handler: %v", err)
		}

		var requestBody map[string]interface{}
		if err := json.Unmarshal(body, &requestBody); err != nil {
			t.Fatalf("Failed to parse request body in next handler: %v", err)
		}

		if requestBody["test"] != "data" {
			t.Errorf("Expected body to contain test:data in next handler, got %v", requestBody)
		}

		rw.WriteHeader(http.StatusOK)
		if _, err := rw.Write([]byte("OK")); err != nil {
			t.Fatalf("Failed to write response: %v", err)
		}
	})

	handler, err := New(context.Background(), nextHandler, cfg, "test-forward-auth-body")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "http://localhost", bytes.NewBufferString(`{"test":"data"}`))
	req.Header.Set("Content-Type", "application/json")

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, recorder.Code)
	}

	if body := recorder.Body.String(); body != "OK" {
		t.Errorf("Expected body 'OK', got '%s'", body)
	}
}

func TestForwardAuthBody_FailedAuth(t *testing.T) {
	// Create a mock forward auth server that returns unauthorized
	mockAuthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Auth-Error", "Invalid credentials")
		w.WriteHeader(http.StatusUnauthorized)
		if _, err := w.Write([]byte("Unauthorized")); err != nil {
			t.Fatalf("Failed to write response: %v", err)
		}
	}))
	defer mockAuthServer.Close()

	cfg := &Config{
		ForwardAuthURL: mockAuthServer.URL,
	}

	nextHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		t.Error("Next handler should not be called when auth fails")
	})

	handler, err := New(context.Background(), nextHandler, cfg, "test-forward-auth-body")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "http://localhost", bytes.NewBufferString(`{"test":"data"}`))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusUnauthorized {
		t.Errorf("Expected status code %d, got %d", http.StatusUnauthorized, recorder.Code)
	}

	if recorder.Header().Get("X-Auth-Error") != "Invalid credentials" {
		t.Error("Error header was not forwarded")
	}

	if body := recorder.Body.String(); body != "Unauthorized" {
		t.Errorf("Expected body 'Unauthorized', got '%s'", body)
	}
}

func TestForwardAuthBody_InvalidURL(t *testing.T) {
	cfg := &Config{
		ForwardAuthURL: "http://invalid-url",
	}

	nextHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		t.Error("Next handler should not be called when auth request fails")
	})

	handler, err := New(context.Background(), nextHandler, cfg, "test-forward-auth-body")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "http://localhost", bytes.NewBufferString(`{"test":"data"}`))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusInternalServerError {
		t.Errorf("Expected status code %d, got %d", http.StatusInternalServerError, recorder.Code)
	}
}

func TestForwardAuthBody_EmptyBody(t *testing.T) {
	mockAuthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("Failed to read forwarded request body: %v", err)
		}
		if len(body) != 0 {
			t.Errorf("Expected empty body, got %s", string(body))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer mockAuthServer.Close()

	cfg := &Config{
		ForwardAuthURL: mockAuthServer.URL,
	}

	nextHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatalf("Failed to read request body in next handler: %v", err)
		}
		if len(body) != 0 {
			t.Errorf("Expected empty body in next handler, got %s", string(body))
		}
		rw.WriteHeader(http.StatusOK)
	})

	handler, _ := New(context.Background(), nextHandler, cfg, "test-forward-auth-body")

	req := httptest.NewRequest(http.MethodPost, "http://localhost", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, recorder.Code)
	}
}

func TestForwardAuthBody_InvalidRequestBody(t *testing.T) {
	cfg := &Config{
		ForwardAuthURL: "http://localhost",
	}

	handler, _ := New(context.Background(), nil, cfg, "test-forward-auth-body")

	// Create a request with a body that will return an error when read
	req := httptest.NewRequest(http.MethodPost, "http://localhost", &errorReader{})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusInternalServerError {
		t.Errorf("Expected status code %d, got %d", http.StatusInternalServerError, recorder.Code)
	}
}

// errorReader is a mock io.Reader that always returns an error
type errorReader struct{}

func (e *errorReader) Read(_ []byte) (int, error) {
	return 0, errors.New("mock read error")
}

func TestCreateConfig(t *testing.T) {
	config := CreateConfig()
	if config == nil {
		t.Fatal("CreateConfig() returned nil")
		return
	}
	if config.ForwardAuthURL != "" {
		t.Errorf("Expected empty ForwardAuthURL, got %s", config.ForwardAuthURL)
	}
}

// testCase represents a test case for New function validation.
type testCase struct {
	config      *Config // 8-byte pointer
	name        string  // 16-byte string
	expectError bool    // 1-byte bool
}

func TestNew_Validation(t *testing.T) {
	testCases := []testCase{
		{
			name: "Valid configuration",
			config: &Config{
				ForwardAuthURL: "http://auth-service:9000/auth",
			},
			expectError: false,
		},
		{
			name:        "Nil config",
			config:      nil,
			expectError: true,
		},
		{
			name: "Empty URL",
			config: &Config{
				ForwardAuthURL: "",
			},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(context.Background(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), tc.config, "test")
			if tc.expectError && err == nil {
				t.Error("Expected error but got nil")
			}
			if !tc.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
		})
	}
}

func TestForwardAuthBody_InvalidRequestCreation(t *testing.T) {
	cfg := &Config{
		ForwardAuthURL: "http://localhost\x00invalid", // Invalid URL with null byte
	}

	handler, err := New(context.Background(), nil, cfg, "test-forward-auth-body")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "http://localhost", bytes.NewBufferString(`{"test":"data"}`))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusInternalServerError {
		t.Errorf("Expected status code %d, got %d", http.StatusInternalServerError, recorder.Code)
	}

	if body := recorder.Body.String(); body != "Error creating forward auth request\n" {
		t.Errorf("Expected error message about request creation, got: %s", body)
	}
}

func TestForwardAuthBody_AuthResponseHeaders(t *testing.T) {
	mockAuthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Xenith-Merchant-Id", "123")
		w.Header().Set("Xenith-Merchant-User-Email", "test@example.com")
		w.Header().Set("Other-Header", "should-not-forward")
		w.WriteHeader(http.StatusOK)
	}))
	defer mockAuthServer.Close()

	cfg := &Config{
		ForwardAuthURL:      mockAuthServer.URL,
		AuthResponseHeaders: []string{"Xenith-Merchant-Id", "Xenith-Merchant-User-Email"},
	}

	nextHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// Check that only configured headers are forwarded
		if req.Header.Get("Xenith-Merchant-Id") != "123" {
			t.Error("Expected Xenith-Merchant-Id header to be forwarded")
		}
		if req.Header.Get("Xenith-Merchant-User-Email") != "test@example.com" {
			t.Error("Expected Xenith-Merchant-User-Email header to be forwarded")
		}
		if req.Header.Get("Other-Header") != "" {
			t.Error("Other-Header should not be forwarded")
		}
		rw.WriteHeader(http.StatusOK)
	})

	handler, _ := New(context.Background(), nextHandler, cfg, "test-forward-auth-body")

	req := httptest.NewRequest(http.MethodPost, "http://localhost", bytes.NewBufferString(`{"test":"data"}`))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, recorder.Code)
	}
}

func TestForwardAuthBody_TrustForwardHeader(t *testing.T) {
	mockAuthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify forwarded headers
		if r.Header.Get("X-Forwarded-For") != "1.2.3.4" {
			t.Errorf("Expected X-Forwarded-For: 1.2.3.4, got %s", r.Header.Get("X-Forwarded-For"))
		}
		if r.Header.Get("X-Forwarded-Proto") != "https" {
			t.Errorf("Expected X-Forwarded-Proto: https, got %s", r.Header.Get("X-Forwarded-Proto"))
		}
		if r.Header.Get("X-Forwarded-Host") != "example.com" {
			t.Errorf("Expected X-Forwarded-Host: example.com, got %s", r.Header.Get("X-Forwarded-Host"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer mockAuthServer.Close()

	cfg := &Config{
		ForwardAuthURL:     mockAuthServer.URL,
		TrustForwardHeader: true,
	}

	handler, _ := New(context.Background(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), cfg, "test-forward-auth-body")

	req := httptest.NewRequest(http.MethodPost, "http://localhost", nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "example.com")

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, recorder.Code)
	}
}

func TestCreateConfig_Defaults(t *testing.T) {
	config := CreateConfig()
	if config == nil {
		t.Fatal("CreateConfig() returned nil")
	}
	if config.ForwardAuthURL != "" {
		t.Errorf("Expected empty ForwardAuthURL, got %s", config.ForwardAuthURL)
	}
	if !reflect.DeepEqual(config.AuthResponseHeaders, []string{}) {
		t.Errorf("Expected empty AuthResponseHeaders, got %v", config.AuthResponseHeaders)
	}
	if config.TrustForwardHeader {
		t.Error("Expected TrustForwardHeader to be false by default")
	}
	if config.MaxBodySize != -1 {
		t.Errorf("Expected MaxBodySize to be -1 by default, got %d", config.MaxBodySize)
	}
}

func TestForwardAuthBody_MaxBodySize(t *testing.T) {
	mockAuthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer mockAuthServer.Close()

	tests := []struct {
		name           string
		maxBodySize    int64
		requestBody    string
		expectedStatus int
	}{
		{
			name:           "Body within limit",
			maxBodySize:    100,
			requestBody:    "small body",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Body exceeds limit",
			maxBodySize:    5,
			requestBody:    "this body is too large",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "No limit",
			maxBodySize:    -1,
			requestBody:    strings.Repeat("large body ", 1000),
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				ForwardAuthURL: mockAuthServer.URL,
				MaxBodySize:    tt.maxBodySize,
			}

			handler, _ := New(context.Background(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}), cfg, "test-forward-auth-body")

			req := httptest.NewRequest(http.MethodPost, "http://localhost", strings.NewReader(tt.requestBody))
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)

			if recorder.Code != tt.expectedStatus {
				t.Errorf("Expected status code %d, got %d", tt.expectedStatus, recorder.Code)
			}
		})
	}
}

func TestForwardAuthBody_HeaderField(t *testing.T) {
	mockAuthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Auth-User", "testuser")
		w.WriteHeader(http.StatusOK)
	}))
	defer mockAuthServer.Close()

	cfg := &Config{
		ForwardAuthURL: mockAuthServer.URL,
		HeaderField:    "X-Auth-User",
	}

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Auth-User") != "testuser" {
			t.Error("Expected X-Auth-User header to be forwarded")
		}
		w.WriteHeader(http.StatusOK)
	})

	handler, _ := New(context.Background(), nextHandler, cfg, "test-forward-auth-body")

	req := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, recorder.Code)
	}
}

func TestForwardAuthBody_PreserveRequestMethod(t *testing.T) {
	var receivedMethod string
	mockAuthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		w.WriteHeader(http.StatusOK)
	}))
	defer mockAuthServer.Close()

	tests := []struct {
		name               string
		preserveMethod     bool
		requestMethod      string
		expectedAuthMethod string
	}{
		{
			name:               "Preserve original method",
			preserveMethod:     true,
			requestMethod:      http.MethodPut,
			expectedAuthMethod: http.MethodPut,
		},
		{
			name:               "Don't preserve method",
			preserveMethod:     false,
			requestMethod:      http.MethodPut,
			expectedAuthMethod: http.MethodGet,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				ForwardAuthURL:        mockAuthServer.URL,
				PreserveRequestMethod: tt.preserveMethod,
			}

			handler, _ := New(context.Background(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}), cfg, "test-forward-auth-body")

			req := httptest.NewRequest(tt.requestMethod, "http://localhost", nil)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)

			if receivedMethod != tt.expectedAuthMethod {
				t.Errorf("Expected auth request method %s, got %s", tt.expectedAuthMethod, receivedMethod)
			}
		})
	}
}

func TestForwardAuthBody_AuthResponseHeadersRegex(t *testing.T) {
	mockAuthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Auth-User", "testuser")
		w.Header().Set("X-Auth-Role", "admin")
		w.Header().Set("Other-Header", "value")
		w.WriteHeader(http.StatusOK)
	}))
	defer mockAuthServer.Close()

	cfg := &Config{
		ForwardAuthURL:           mockAuthServer.URL,
		AuthResponseHeadersRegex: "^X-Auth-.*",
	}

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Auth-User") != "testuser" {
			t.Error("Expected X-Auth-User header to be forwarded")
		}
		if r.Header.Get("X-Auth-Role") != "admin" {
			t.Error("Expected X-Auth-Role header to be forwarded")
		}
		if r.Header.Get("Other-Header") != "" {
			t.Error("Other-Header should not be forwarded")
		}
		w.WriteHeader(http.StatusOK)
	})

	handler, _ := New(context.Background(), nextHandler, cfg, "test-forward-auth-body")

	req := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, recorder.Code)
	}
}

func TestForwardAuthBody_AuthRequestHeaders(t *testing.T) {
	mockAuthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Allow-Header") != "yes" {
			t.Error("Expected Allow-Header to be forwarded")
		}
		if r.Header.Get("Block-Header") != "" {
			t.Error("Block-Header should not be forwarded")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer mockAuthServer.Close()

	cfg := &Config{
		ForwardAuthURL:     mockAuthServer.URL,
		AuthRequestHeaders: []string{"Allow-Header"},
	}

	handler, _ := New(context.Background(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), cfg, "test-forward-auth-body")

	req := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
	req.Header.Set("Allow-Header", "yes")
	req.Header.Set("Block-Header", "no")

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, recorder.Code)
	}
}

func TestForwardAuthBody_PreserveLocationHeader(t *testing.T) {
	tests := []struct {
		name             string
		preserveLocation bool
		location         string
		expectedLocation string
	}{
		{
			name:             "Preserve location header",
			preserveLocation: true,
			location:         "http://example.com/login",
			expectedLocation: "http://example.com/login",
		},
		{
			name:             "Don't preserve location header",
			preserveLocation: false,
			location:         "http://example.com/login",
			expectedLocation: "http://example.com/login",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockAuthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", tt.location)
				w.WriteHeader(http.StatusFound)
			}))
			defer mockAuthServer.Close()

			cfg := &Config{
				ForwardAuthURL:         mockAuthServer.URL,
				PreserveLocationHeader: tt.preserveLocation,
			}

			handler, _ := New(context.Background(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Error("Next handler should not be called on redirect")
			}), cfg, "test-forward-auth-body")

			req := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)

			if recorder.Code != http.StatusFound {
				t.Errorf("Expected status code %d, got %d", http.StatusFound, recorder.Code)
			}

			if location := recorder.Header().Get("Location"); location != tt.expectedLocation {
				t.Errorf("Expected Location header %s, got %s", tt.expectedLocation, location)
			}
		})
	}
}

func TestForwardAuthBody_InvalidHeadersRegex(t *testing.T) {
	mockAuthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer mockAuthServer.Close()

	cfg := &Config{
		ForwardAuthURL:           mockAuthServer.URL,
		AuthResponseHeadersRegex: "[invalid regex",
	}

	_, err := New(context.Background(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), cfg, "test")
	if err == nil {
		t.Error("Expected error for invalid regex pattern")
	}
}

func TestForwardAuthBody_BodyAndHeadersPreservation(t *testing.T) {
	type testRequest struct {
		Message string `json:"message"`
	}

	mockAuthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the body was forwarded correctly
		var req testRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("Failed to decode forwarded body: %v", err)
		}
		if req.Message != "test message" {
			t.Errorf("Expected message 'test message', got '%s'", req.Message)
		}

		w.Header().Set("X-Auth-User", "testuser")
		w.WriteHeader(http.StatusOK)
	}))
	defer mockAuthServer.Close()

	cfg := &Config{
		ForwardAuthURL:      mockAuthServer.URL,
		AuthResponseHeaders: []string{"X-Auth-User"},
		MaxBodySize:         1048576,
	}

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the body is preserved
		var req testRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("Failed to decode preserved body: %v", err)
		}
		if req.Message != "test message" {
			t.Errorf("Expected message 'test message', got '%s'", req.Message)
		}

		// Verify the auth header was forwarded
		if r.Header.Get("X-Auth-User") != "testuser" {
			t.Error("Expected X-Auth-User header to be forwarded")
		}

		w.WriteHeader(http.StatusOK)
	})

	handler, _ := New(context.Background(), nextHandler, cfg, "test-forward-auth-body")

	body := testRequest{Message: "test message"}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "http://localhost", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, recorder.Code)
	}
}
