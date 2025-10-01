package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/blessnetwork/bless-web-ingress/ingress"
	ung "github.com/dillonstreator/go-unique-name-generator"
	"github.com/dillonstreator/go-unique-name-generator/dictionaries"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
	"github.com/segmentio/ksuid"
	"golang.org/x/net/html"
)

type DB interface {
	GetHostDataByHost(host string) (*ingress.Host, error)
	GetHostDataByDestination(destination string) (*ingress.Host, error)
	InsertHostData(host ingress.Host) error
	UpdateHostData(host ingress.Host) error
}

type api struct {
	db   DB
	addr string
	srv  *http.Server
}

func newAPI(addr string, db DB) *api {

	// Uses default mux
	srv := &http.Server{Addr: addr}

	a := &api{
		db:   db,
		addr: addr,
		srv:  srv,
	}

	return a
}

func (a *api) Start() error {

	http.HandleFunc("/", a.handleRequest)
	http.HandleFunc("/insert", a.handleInsertHost)
	http.HandleFunc("/update", a.handleUpdateHost)
	http.HandleFunc("/health", handleHealth)
	http.Handle("/metrics", promhttp.Handler())

	log.Info().Msgf("Server started on address %s", a.addr)

	return a.srv.ListenAndServe()
}

func (a *api) Shutdown(ctx context.Context) error {
	return a.srv.Shutdown(ctx)
}

func (a *api) handleRequest(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	reqCount.WithLabelValues(r.URL.Path).Inc()
	defer func() {
		reqDuration.WithLabelValues(r.URL.Path).Observe(time.Since(start).Seconds())
	}()

	log.Info().Msgf("Received request for host: %s, path: %s", r.Host, r.URL.Path)

	data, err := a.db.GetHostDataByHost(r.Host)
	if err != nil {
		http.NotFound(w, r)
		log.Error().Err(err).Msg("Host not found")
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		log.Error().Err(err).Msg("Failed to read request body")
		return
	}
	defer r.Body.Close()

	var bodyData map[string]any
	if len(bodyBytes) > 0 {
		if err := json.Unmarshal(bodyBytes, &bodyData); err != nil {
			http.Error(w, "Failed to parse request body as JSON", http.StatusBadRequest)
			log.Error().Err(err).Msg("Failed to parse request body as JSON")
			return
		}
	} else {
		bodyData = make(map[string]any)
	}

	stdin := map[string]any{
		"path":   r.URL.Path,
		"method": r.Method,
		"body":   bodyData, // Use the parsed JSON object directly
	}
	stdinJSON, _ := json.Marshal(stdin)

	var permissions []string
	if err := json.Unmarshal([]byte(data.PermissionsString), &permissions); err != nil {
		http.Error(w, "Failed to unmarshal permissions", http.StatusInternalServerError)
		log.Error().Err(err).Msg("Failed to unmarshal permissions")
		return
	}

	requestBody := map[string]any{
		"function_id": data.Destination,
		"method":      data.EntryMethod,
		"parameters":  nil,
		"config": map[string]any{
			"permissions":     permissions,
			"stdin":           string(stdinJSON),
			"env_vars":        []map[string]string{},
			"number_of_nodes": 1,
		},
	}

	// Add debug logging for stdin configuration

	log.Debug().Str("stdin_config", string(stdinJSON)).Msg("Stdin configuration")

	// Add debug logging
	log.Debug().Any("request_body", requestBody).Msg("Request body before sending to external API")

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		http.Error(w, "Failed to marshal request body", http.StatusInternalServerError)
		log.Error().Err(err).Msgf("Failed to marshal request body for host: %s, path: %s", r.Host, r.URL.Path)
		return
	}

	if len(cfg.externalAPIURLs) == 0 || cfg.externalAPIURLs[0] == "" {
		log.Fatal().Msg("EXTERNAL_API_URL environment variable is required")
	}

	var resp *http.Response
	var body []byte

	if data.NumberOfNodes > 1 {
		log.Info().Int("number_of_nodes", data.NumberOfNodes).Msg("Using parallel requests")
		resp, body, err = makeParallelRequests(cfg.externalAPIURLs, jsonData)
	} else {
		log.Info().Msg("Using fallback requests")
		resp, body, err = makeFallbackRequest(cfg.externalAPIURLs, jsonData)
	}

	if err != nil {
		http.Error(w, "Failed to call external APIs", http.StatusInternalServerError)
		log.Error().Err(err).Msgf("All external API calls failed for host: %s, path: %s", r.Host, r.URL.Path)
		return
	}

	if data.ReturnType == ReturnTypeRaw {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		if _, err := w.Write(body); err != nil {
			http.Error(w, "Failed to write response", http.StatusInternalServerError)
			log.Error().Err(err).Msg("Failed to write response")
		}
		log.Info().Msg("Response sent successfully")
		return
	}

	var apiResponse APIResponse
	if err := json.Unmarshal(body, &apiResponse); err != nil {
		http.Error(w, "Failed to unmarshal response body", http.StatusInternalServerError)
		log.Error().Err(err).Msg("Failed to unmarshal response body")
		return
	}

	if len(apiResponse.Results) == 0 {
		http.Error(w, "No results in response", http.StatusInternalServerError)
		log.Error().Msg("No results in response")
		return
	}

	// Find result with highest consensus
	highestConsensus := apiResponse.Results[0]
	for _, result := range apiResponse.Results[1:] {
		if result.Frequency > highestConsensus.Frequency {
			highestConsensus = result
		}
	}

	stdout := highestConsensus.Result.Stdout
	// totalNodes := len(apiResponse.Cluster.Peers)
	// consensusNodes := len(highestConsensus.Peers)
	// consensusPercentage := float64(highestConsensus.Frequency)

	// Check if the response is base64 encoded with content type
	if cached, found := getCachedResponse(r.Host, r.URL.Path, data.Destination); found {
		w.Header().Set("Content-Type", cached.ContentType)
		w.Header().Set("X-Cache", "HIT")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(cached.Data); err != nil {
			http.Error(w, "Failed to write response", http.StatusInternalServerError)
			log.Error().Err(err).Msg("Failed to write cached response")
		}
		return
	}

	if matched, _ := regexp.MatchString(`^data:([^;]+);base64,`, stdout); matched {
		parts := strings.SplitN(stdout, ",", 2)
		contentType := strings.SplitN(parts[0], ":", 2)[1]       // Get full content type
		contentType = strings.TrimSuffix(contentType, ";base64") // Remove base64 suffix

		decoded, err := base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			http.Error(w, "Failed to decode base64 response", http.StatusInternalServerError)
			log.Error().Err(err).Msg("Failed to decode base64 response")
			return
		}

		// Cache the decoded response
		setCachedResponse(r.Host, r.URL.Path, data.Destination, contentType, decoded)

		w.Header().Set("Content-Type", contentType)
		w.Header().Set("X-Cache", "MISS")
		w.WriteHeader(resp.StatusCode)

		if _, err := w.Write(decoded); err != nil {
			http.Error(w, "Failed to write response", http.StatusInternalServerError)
			log.Error().Err(err).Msg("Failed to write response")
		}
	} else {
		// Set Content-Type based on ReturnType only for non-base64 responses
		switch data.ReturnType {
		case ReturnTypeText:
			w.Header().Set("Content-Type", "text/plain")
		case ReturnTypeJSON:
			w.Header().Set("Content-Type", "application/json")
		case ReturnTypeHTML:
			w.Header().Set("Content-Type", "text/html")
			// stdout = injectHTMLBanner(stdout, consensusNodes, totalNodes, consensusPercentage)
		default:
			w.Header().Set("Content-Type", "text/plain")
		}
		w.WriteHeader(resp.StatusCode)
		if _, err := w.Write([]byte(stdout)); err != nil {
			http.Error(w, "Failed to write response", http.StatusInternalServerError)
			log.Error().Err(err).Msg("Failed to write response")
		}
	}
	log.Info().Msg("Response sent successfully")
}

func (a *api) handleInsertHost(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	reqCount.WithLabelValues(r.URL.Path).Inc()
	defer func() {
		reqDuration.WithLabelValues(r.URL.Path).Observe(time.Since(start).Seconds())
	}()

	log.Info().Msg("Received insert host request")

	if !a.allowedHost(r.Host) {
		a.handleRequest(w, r)
		return
	}

	var data ingress.Host
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Error().Err(err).Msg("Failed to decode request body")
		return
	}
	if data.Destination == "" || data.EntryMethod == "" {
		http.Error(w, "Destination and EntryMethod are required", http.StatusBadRequest)
		log.Error().Msg("Destination and EntryMethod are required")
		return
	}

	// Always set PermissionsString regardless of array length
	permissionsJSON, err := json.Marshal(data.Permissions)
	if err != nil {
		http.Error(w, "Failed to process permissions", http.StatusBadRequest)
		log.Error().Err(err).Msg("Failed to marshal permissions")
		return
	}
	data.PermissionsString = string(permissionsJSON)

	pattern := `^bafy[a-zA-Z0-9]{50,}$`
	matched, err := regexp.MatchString(pattern, data.Destination)
	if err != nil || !matched {
		http.Error(w, "Invalid destination format", http.StatusBadRequest)
		log.Error().Msg("Invalid destination format")
		return
	}

	// Check if the destination is unique
	existingData, err := a.db.GetHostDataByDestination(data.Destination)
	if err == nil && existingData != nil {
		http.Error(w, "Destination already exists", http.StatusConflict)
		log.Error().Msg("Destination already exists")
		return
	}

	nameGenerator := ung.NewUniqueNameGenerator(
		ung.WithDictionaries(
			[][]string{
				dictionaries.Colors,
				dictionaries.Animals,
				dictionaries.Names,
			},
		),
		ung.WithSeparator("-"),
	)

	if cfg.rootURL == "" {
		log.Fatal().Msg("ROOT_URL environment variable is required")
	}

	data.Host = nameGenerator.Generate() + "-" + data.Destination[len(data.Destination)-8:] + "." + cfg.rootURL
	data.Created = time.Now()
	data.Updated = time.Now()
	data.UpdaterID = ksuid.New().String()
	err = a.db.InsertHostData(data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Error().Err(err).Msg("Failed to insert host data")
		return
	}

	deployCount.Inc()
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Error().Err(err).Msg("Failed to encode response")
		return
	}
	log.Info().Msg("Host data inserted successfully")
}

func (a *api) handleUpdateHost(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	reqCount.WithLabelValues(r.URL.Path).Inc()
	defer func() {
		reqDuration.WithLabelValues(r.URL.Path).Observe(time.Since(start).Seconds())
	}()

	log.Info().Msg("Received update host request")

	if !a.allowedHost(r.Host) {
		a.handleRequest(w, r)
		return
	}

	var data ingress.Host
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Error().Err(err).Msg("Failed to decode request body")
		return
	}
	if data.Destination == "" || data.UpdaterID == "" {
		http.Error(w, "Destination and UpdaterID are required", http.StatusBadRequest)
		log.Error().Msg("Destination and UpdaterID are required")
		return
	}

	// Always set PermissionsString regardless of array length
	permissionsJSON, err := json.Marshal(data.Permissions)
	if err != nil {
		http.Error(w, "Failed to process permissions", http.StatusBadRequest)
		log.Error().Err(err).Msg("Failed to marshal permissions")
		return
	}
	data.PermissionsString = string(permissionsJSON)

	pattern := `^bafy[a-zA-Z0-9]{50,}$`
	matched, err := regexp.MatchString(pattern, data.Destination)
	if err != nil || !matched {
		http.Error(w, "Invalid destination format", http.StatusBadRequest)
		log.Error().Msg("Invalid destination format")
		return
	}

	existingData, err := a.db.GetHostDataByHost(data.Host)
	if err != nil {
		http.Error(w, "Host not found", http.StatusNotFound)
		log.Error().Err(err).Msg("Host not found")
		return
	}

	if existingData.UpdaterID != data.UpdaterID {
		http.Error(w, "UpdaterID does not match", http.StatusForbidden)
		log.Error().Msg("UpdaterID does not match")
		return
	}

	data.Updated = time.Now()
	err = a.db.UpdateHostData(data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Error().Err(err).Msg("Failed to update host data")
		return
	}

	updateCount.Inc()
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Error().Err(err).Msg("Failed to encode response")
		return
	}
	log.Info().Msgf("Host data updated successfully for host: %s", data.Host)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	reqCount.WithLabelValues(r.URL.Path).Inc()
	defer func() {
		reqDuration.WithLabelValues(r.URL.Path).Observe(time.Since(start).Seconds())
	}()

	log.Info().Msg("Received health check request")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(`{"status":"ok"}`)); err != nil {
		http.Error(w, "Failed to write response", http.StatusInternalServerError)
		log.Error().Err(err).Msg("Failed to write response")
		return
	}
	log.Info().Msg("Health check response sent successfully")
}

func injectHTMLBanner(htmlContent string, consensusNodes, totalNodes int, consensusPercentage float64) string {
	consensusColor := "#28a745" // Green for high consensus
	if consensusPercentage < 66 {
		consensusColor = "#ffc107" // Yellow for medium consensus
	}
	if consensusPercentage < 50 {
		consensusColor = "#dc3545" // Red for low consensus
	}

	banner := fmt.Sprintf(`<div style="background-color: #f8f9fa; padding: 10px; text-align: center; font-family: sans-serif; border-bottom: 1px solid #dee2e6;">
		Executed on %d of %d nodes with <span style="color: %s">%.0f%% consensus</span>
	</div>`, consensusNodes, totalNodes, consensusColor, consensusPercentage)

	// Parse HTML
	doc, err := html.Parse(strings.NewReader(htmlContent))
	if err != nil {
		// If parsing fails, fall back to prepending
		return banner + htmlContent
	}

	// Find the body tag
	var body *html.Node
	var findBody func(*html.Node)
	findBody = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "body" {
			body = n
			return
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			findBody(c)
		}
	}
	findBody(doc)

	if body != nil {
		// Parse banner as a separate document
		bannerDoc, err := html.Parse(strings.NewReader(banner))
		if err != nil {
			return banner + htmlContent
		}

		// Find the div node in the banner document
		var bannerDiv *html.Node
		var findDiv func(*html.Node)
		findDiv = func(n *html.Node) {
			if n.Type == html.ElementNode && n.Data == "div" {
				bannerDiv = n
				return
			}
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				findDiv(c)
			}
		}
		findDiv(bannerDoc)

		if bannerDiv != nil {
			// Clone the banner div and its children
			bannerClone := &html.Node{
				Type:     bannerDiv.Type,
				DataAtom: bannerDiv.DataAtom,
				Data:     bannerDiv.Data,
				Attr:     append([]html.Attribute(nil), bannerDiv.Attr...),
			}

			// Clone children
			for c := bannerDiv.FirstChild; c != nil; c = c.NextSibling {
				clone := &html.Node{
					Type:     c.Type,
					DataAtom: c.DataAtom,
					Data:     c.Data,
					Attr:     append([]html.Attribute(nil), c.Attr...),
				}
				bannerClone.AppendChild(clone)
			}

			// Insert the cloned banner at the start of body
			body.InsertBefore(bannerClone, body.FirstChild)

			// Render modified HTML
			var buf bytes.Buffer
			if err := html.Render(&buf, doc); err == nil {
				return buf.String()
			}
		}
	}

	// Fallback to prepending if anything fails
	return banner + htmlContent
}

func (a *api) allowedHost(host string) bool {
	switch host {
	case "localhost", "127.0.0.1", a.addr:
		return true
	case cfg.rootHost:
		return true

	default:
		return false
	}
}
