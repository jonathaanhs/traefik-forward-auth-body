// Package traefik_forward_auth_body is a Traefik plugin that forwards request bodies in forward authentication.
//
//revive:disable:var-naming
package traefik_forward_auth_body

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
)

// Config holds the plugin configuration.
type Config struct {
	ForwardAuthURL string `json:"forwardAuthURL,omitempty"`
}

// CreateConfig creates and initializes the plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

// Body is a plugin that forwards request bodies in forward authentication.
type Body struct {
	next           http.Handler // 8-byte pointer
	forwardAuthURL string       // 16-byte string
	name           string       // 16-byte string
}

// New creates a new Body plugin.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config == nil {
		return nil, fmt.Errorf("configuration cannot be nil")
	}

	if config.ForwardAuthURL == "" {
		return nil, fmt.Errorf("forwardAuthURL cannot be empty")
	}

	return &Body{
		next:           next,
		forwardAuthURL: config.ForwardAuthURL,
		name:           name,
	}, nil
}

func (f *Body) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Read the request body
	body, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(rw, "Error reading request body", http.StatusInternalServerError)
		return
	}

	// Create a new request to the forward auth service
	forwardReq, err := http.NewRequestWithContext(req.Context(), req.Method, f.forwardAuthURL, bytes.NewBuffer(body))
	if err != nil {
		http.Error(rw, "Error creating forward auth request", http.StatusInternalServerError)
		return
	}

	// Copy headers from original request
	forwardReq.Header = req.Header.Clone()

	// Send the request to the forward auth service
	client := &http.Client{}
	resp, err := client.Do(forwardReq)
	if err != nil {
		http.Error(rw, "Error sending forward auth request", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Copy response headers from auth service
	for key, values := range resp.Header {
		for _, value := range values {
			rw.Header().Add(key, value)
		}
	}

	// If forward auth fails, return the error response
	if resp.StatusCode != http.StatusOK {
		rw.WriteHeader(resp.StatusCode)
		if _, err := io.Copy(rw, resp.Body); err != nil {
			http.Error(rw, "Error copying response body", http.StatusInternalServerError)
			return
		}
		return
	}

	// Forward the auth service response headers to the next handler
	for key, values := range resp.Header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	// Restore the request body for the next handler
	req.Body = io.NopCloser(bytes.NewBuffer(body))
	f.next.ServeHTTP(rw, req)
}
