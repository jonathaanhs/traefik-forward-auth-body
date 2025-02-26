// Package traefik_forward_auth_body is a Traefik plugin that forwards request bodies in forward authentication.
package traefik_forward_auth_body

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"time"
)

const (
	xForwardedURI    = "X-Forwarded-Uri"
	xForwardedMethod = "X-Forwarded-Method"
)

// hopHeaders Hop-by-hop headers to be removed in the authentication request.
var hopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Te", // canonicalized version of "TE"
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

// Config represents the plugin configuration.
type Config struct {
	ForwardAuthURL           string   `json:"forwardAuthURL,omitempty"`
	AuthResponseHeaders      []string `json:"authResponseHeaders,omitempty"`
	AuthResponseHeadersRegex string   `json:"authResponseHeadersRegex,omitempty"`
	AuthRequestHeaders       []string `json:"authRequestHeaders,omitempty"`
	TrustForwardHeader       bool     `json:"trustForwardHeader,omitempty"`
	HeaderField              string   `json:"headerField,omitempty"`
	PreserveLocationHeader   bool     `json:"preserveLocationHeader,omitempty"`
	PreserveRequestMethod    bool     `json:"preserveRequestMethod,omitempty"`
	ForwardBody              bool     `json:"forwardBody,omitempty"`
	MaxBodySize              int64    `json:"maxBodySize,omitempty"`
}

// CreateConfig creates and initializes the plugin configuration.
func CreateConfig() *Config {
	return &Config{
		AuthResponseHeaders:    []string{},
		AuthRequestHeaders:     []string{},
		TrustForwardHeader:     false,
		PreserveLocationHeader: false,
		PreserveRequestMethod:  false,
		ForwardBody:            true, // Forward body by default for backward compatibility
		MaxBodySize:            -1,   // No limit by default
	}
}

// Body represents the forward auth middleware instance.
type Body struct {
	next                   http.Handler
	forwardAuthURL         string
	name                   string
	authRespHeaders        []string
	authRespHeadersRegex   *regexp.Regexp
	authRequestHeaders     []string
	trustForwardHeader     bool
	headerField            string
	preserveLocationHeader bool
	preserveRequestMethod  bool
	forwardBody            bool
	maxBodySize            int64
	client                 http.Client
}

var errBodyTooLarge = errors.New("request body too large")

// New creates a new Body plugin.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config == nil {
		return nil, fmt.Errorf("configuration cannot be nil")
	}

	if config.ForwardAuthURL == "" {
		return nil, fmt.Errorf("forwardAuthURL cannot be empty")
	}

	var authRespHeadersRegex *regexp.Regexp
	if config.AuthResponseHeadersRegex != "" {
		re, err := regexp.Compile(config.AuthResponseHeadersRegex)
		if err != nil {
			return nil, fmt.Errorf("error compiling regular expression %s: %w", config.AuthResponseHeadersRegex, err)
		}
		authRespHeadersRegex = re
	}

	// Use default value for maxBodySize if not set
	maxBodySize := config.MaxBodySize
	if maxBodySize == 0 {
		maxBodySize = -1 // Default value from CreateConfig
	}

	fa := &Body{
		next:                   next,
		forwardAuthURL:         config.ForwardAuthURL,
		name:                   name,
		authRespHeaders:        config.AuthResponseHeaders,
		authRespHeadersRegex:   authRespHeadersRegex,
		authRequestHeaders:     config.AuthRequestHeaders,
		trustForwardHeader:     config.TrustForwardHeader,
		headerField:            config.HeaderField,
		preserveLocationHeader: config.PreserveLocationHeader,
		preserveRequestMethod:  config.PreserveRequestMethod,
		forwardBody:            config.ForwardBody,
		maxBodySize:            maxBodySize,
		client: http.Client{
			CheckRedirect: func(r *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Timeout: 30 * time.Second,
		},
	}

	return fa, nil
}

func (fa *Body) readBodyBytes(req *http.Request) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}

	// If maxBodySize is not set (negative), read the entire body
	if fa.maxBodySize < 0 {
		return io.ReadAll(req.Body)
	}

	// Read the entire body
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, fmt.Errorf("reading body bytes: %w", err)
	}

	// Check size after reading
	if int64(len(body)) > fa.maxBodySize {
		return nil, errBodyTooLarge
	}

	return body, nil
}

func (fa *Body) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	forwardReqMethod := http.MethodGet
	if fa.preserveRequestMethod {
		forwardReqMethod = req.Method
	}

	// Read and store the body
	var bodyBytes []byte
	var err error
	if req.Body != nil {
		// Use readBodyBytes which handles maxBodySize correctly
		bodyBytes, err = fa.readBodyBytes(req)
		if errors.Is(err, errBodyTooLarge) {
			http.Error(rw, "Request body is too large", http.StatusUnauthorized)
			return
		}
		if err != nil {
			http.Error(rw, "Error reading request body", http.StatusInternalServerError)
			return
		}
		// Restore the original request body for the next handler
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	// Create forward auth request with or without body based on forwardBody flag
	var forwardReq *http.Request
	if fa.forwardBody && bodyBytes != nil {
		forwardReq, err = http.NewRequestWithContext(req.Context(), forwardReqMethod, fa.forwardAuthURL, bytes.NewReader(bodyBytes))
		// Set Content-Type and Content-Length if body is present
		if req.Header.Get("Content-Type") != "" {
			forwardReq.Header.Set("Content-Type", req.Header.Get("Content-Type"))
		}
		forwardReq.ContentLength = int64(len(bodyBytes))
	} else {
		forwardReq, err = http.NewRequestWithContext(req.Context(), forwardReqMethod, fa.forwardAuthURL, nil)
	}
	if err != nil {
		http.Error(rw, "Error creating forward auth request", http.StatusInternalServerError)
		return
	}

	// Copy and filter headers
	fa.writeHeader(req, forwardReq)

	// Send the request to the forward auth service
	forwardResponse, err := fa.client.Do(forwardReq)
	if err != nil {
		http.Error(rw, fmt.Sprintf("Error sending forward auth request: %v", err), http.StatusInternalServerError)
		return
	}
	defer forwardResponse.Body.Close()

	body, err := io.ReadAll(forwardResponse.Body)
	if err != nil {
		http.Error(rw, "Error reading auth response body", http.StatusInternalServerError)
		return
	}

	// Copy response headers first, regardless of status code
	for key, values := range forwardResponse.Header {
		for _, value := range values {
			rw.Header().Add(key, value)
		}
	}

	// Remove hop-by-hop headers
	for _, h := range hopHeaders {
		rw.Header().Del(h)
	}

	// Handle non-2xx responses
	if forwardResponse.StatusCode < http.StatusOK || forwardResponse.StatusCode >= http.StatusMultipleChoices {
		// Handle redirect
		redirectURL, err := fa.redirectURL(forwardResponse)
		if err == nil && redirectURL.String() != "" {
			rw.Header().Set("Location", redirectURL.String())
		}

		rw.WriteHeader(forwardResponse.StatusCode)
		rw.Write(body)
		return
	}

	// Forward allowed headers from auth response to the original request
	if len(fa.authRespHeaders) > 0 {
		// Clear existing headers that match our auth response headers
		for _, headerName := range fa.authRespHeaders {
			headerKey := http.CanonicalHeaderKey(headerName)
			req.Header.Del(headerKey)
			if values := forwardResponse.Header[headerKey]; len(values) > 0 {
				req.Header[headerKey] = append([]string(nil), values...)
			}
		}
	}

	// Handle regex-based header forwarding
	if fa.authRespHeadersRegex != nil {
		// First, clear any existing headers that match the regex
		for headerKey := range req.Header {
			if fa.authRespHeadersRegex.MatchString(headerKey) {
				req.Header.Del(headerKey)
			}
		}
		// Then, copy matching headers from the auth response
		for headerKey, values := range forwardResponse.Header {
			if fa.authRespHeadersRegex.MatchString(headerKey) {
				req.Header[headerKey] = append([]string(nil), values...)
			}
		}
	}

	// If no specific headers are configured, forward all non-hop-by-hop headers
	if len(fa.authRespHeaders) == 0 && fa.authRespHeadersRegex == nil {
		for key, values := range forwardResponse.Header {
			if !contains(hopHeaders, key) {
				req.Header[key] = append([]string(nil), values...)
			}
		}
	}

	// Restore the request URI
	req.RequestURI = req.URL.RequestURI()

	// Call the next handler
	fa.next.ServeHTTP(rw, req)
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if http.CanonicalHeaderKey(s) == http.CanonicalHeaderKey(item) {
			return true
		}
	}
	return false
}

func (fa *Body) redirectURL(forwardResponse *http.Response) (*url.URL, error) {
	if !fa.preserveLocationHeader {
		return forwardResponse.Location()
	}

	// Preserve the Location header if it exists
	if lv := forwardResponse.Header.Get("Location"); lv != "" {
		return url.Parse(lv)
	}
	return nil, http.ErrNoLocation
}

func (fa *Body) writeHeader(req, forwardReq *http.Request) {
	// Copy all headers
	for key, values := range req.Header {
		for _, value := range values {
			forwardReq.Header.Add(key, value)
		}
	}

	// Remove hop-by-hop headers
	for _, h := range hopHeaders {
		forwardReq.Header.Del(h)
	}

	// Filter headers if auth request headers are specified
	if len(fa.authRequestHeaders) > 0 {
		filteredHeaders := http.Header{}
		for _, headerName := range fa.authRequestHeaders {
			if values := forwardReq.Header[http.CanonicalHeaderKey(headerName)]; len(values) > 0 {
				filteredHeaders[http.CanonicalHeaderKey(headerName)] = append([]string(nil), values...)
			}
		}
		forwardReq.Header = filteredHeaders
	}

	// Handle X-Forwarded headers
	if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		if fa.trustForwardHeader {
			if prior := req.Header.Get("X-Forwarded-For"); prior != "" {
				clientIP = prior
			}
		}
		forwardReq.Header.Set("X-Forwarded-For", clientIP)
	}

	// X-Forwarded-Method
	xMethod := req.Header.Get(xForwardedMethod)
	switch {
	case xMethod != "" && fa.trustForwardHeader:
		forwardReq.Header.Set(xForwardedMethod, xMethod)
	case req.Method != "":
		forwardReq.Header.Set(xForwardedMethod, req.Method)
	default:
		forwardReq.Header.Del(xForwardedMethod)
	}

	// X-Forwarded-Proto
	xfp := req.Header.Get("X-Forwarded-Proto")
	switch {
	case xfp != "" && fa.trustForwardHeader:
		forwardReq.Header.Set("X-Forwarded-Proto", xfp)
	case req.TLS != nil:
		forwardReq.Header.Set("X-Forwarded-Proto", "https")
	default:
		forwardReq.Header.Set("X-Forwarded-Proto", "http")
	}

	// X-Forwarded-Port
	if xfp := req.Header.Get("X-Forwarded-Port"); xfp != "" && fa.trustForwardHeader {
		forwardReq.Header.Set("X-Forwarded-Port", xfp)
	}

	// X-Forwarded-Host
	xfh := req.Header.Get("X-Forwarded-Host")
	switch {
	case xfh != "" && fa.trustForwardHeader:
		forwardReq.Header.Set("X-Forwarded-Host", xfh)
	case req.Host != "":
		forwardReq.Header.Set("X-Forwarded-Host", req.Host)
	default:
		forwardReq.Header.Del("X-Forwarded-Host")
	}

	// X-Forwarded-URI
	xfURI := req.Header.Get(xForwardedURI)
	switch {
	case xfURI != "" && fa.trustForwardHeader:
		forwardReq.Header.Set(xForwardedURI, xfURI)
	case req.URL.RequestURI() != "":
		forwardReq.Header.Set(xForwardedURI, req.URL.RequestURI())
	default:
		forwardReq.Header.Del(xForwardedURI)
	}
}
