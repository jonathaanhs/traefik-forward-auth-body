// Package traefik_forward_auth_body is a Traefik plugin that forwards request bodies in forward authentication.
package traefik_forward_auth_body

import (
	"bytes"
	"context"
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

// ForwardAuthBody is a plugin that forwards request bodies in forward authentication.
type ForwardAuthBody struct {
	next           http.Handler
	forwardAuthURL string
	name           string
}

// New creates a new ForwardAuthBody plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config == nil {
		config = CreateConfig()
	}

	return &ForwardAuthBody{
		next:           next,
		forwardAuthURL: config.ForwardAuthURL,
		name:           name,
	}, nil
}

func (f *ForwardAuthBody) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Read the request body
	body, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(rw, "Error reading request body", http.StatusInternalServerError)
		return
	}

	// Create a new request to the forward auth service
	forwardReq, err := http.NewRequest(req.Method, f.forwardAuthURL, bytes.NewBuffer(body))
	if err != nil {
		http.Error(rw, "Error creating forward auth request", http.StatusInternalServerError)
		return
	}

	// Copy headers from original request
	for key, values := range req.Header {
		for _, value := range values {
			forwardReq.Header.Add(key, value)
		}
	}

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
		io.Copy(rw, resp.Body)
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
