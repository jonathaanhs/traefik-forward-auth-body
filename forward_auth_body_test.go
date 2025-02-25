//revive:disable:var-naming
package traefik_forward_auth_body

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
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
		ForwardAuthURL: mockAuthServer.URL,
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
