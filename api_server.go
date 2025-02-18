package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	ung "github.com/dillonstreator/go-unique-name-generator"
	"github.com/dillonstreator/go-unique-name-generator/dictionaries"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
	"github.com/segmentio/ksuid"
)

func handleRequest(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	reqCount.WithLabelValues(r.URL.Path).Inc()
	defer func() {
		reqDuration.WithLabelValues(r.URL.Path).Observe(time.Since(start).Seconds())
	}()

	log.Info().Msgf("Received request for host: %s, path: %s", r.Host, r.URL.Path)

	data, err := getHostDataByHost(r.Host)
	if err != nil {
		http.NotFound(w, r)
		log.Error().Err(err).Msg("Host not found")
		return
	}

	stdin := map[string]string{"path": r.URL.Path, "method": r.Method}
	stdinJSON, _ := json.Marshal(stdin)
	requestBody := map[string]interface{}{
		"function_id": data.Destination,
		"method":      data.EntryMethod,
		"parameters":  nil,
		"config": map[string]interface{}{
			"permissions":     []interface{}{},
			"stdin":           string(stdinJSON),
			"env_vars":        []map[string]string{},
			"number_of_nodes": 1,
		},
	}

	// Add debug logging for stdin configuration

	log.Debug().Str("stdin_config", string(stdinJSON)).Msg("Stdin configuration")

	// Add debug logging
	log.Debug().Interface("request_body", requestBody).Msg("Request body before sending to external API")

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		http.Error(w, "Failed to marshal request body", http.StatusInternalServerError)
		log.Error().Err(err).Msgf("Failed to marshal request body for host: %s, path: %s", r.Host, r.URL.Path)
		return
	}

	externalAPIURL := os.Getenv("EXTERNAL_API_URL")
	if externalAPIURL == "" {
		log.Fatal().Msg("EXTERNAL_API_URL environment variable is required")
	}

	resp, err := http.Post(externalAPIURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		http.Error(w, "Failed to call external API", http.StatusInternalServerError)
		log.Error().Err(err).Msgf("Failed to call external API at %s for host: %s, path: %s", externalAPIURL, r.Host, r.URL.Path) // More verbose logging
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		http.Error(w, "External API call failed", resp.StatusCode)
		log.Error().Msgf("External API call failed with status: %d at %s for host: %s, path: %s", resp.StatusCode, externalAPIURL, r.Host, r.URL.Path) // More verbose logging
		return
	}

	switch data.ReturnType {
	case "text":
		w.Header().Set("Content-Type", "text/plain")
	case "json":
		w.Header().Set("Content-Type", "application/json")
	case "html":
		w.Header().Set("Content-Type", "text/html")
	case "raw":
		w.Header().Set("Content-Type", "application/json")
	default:
		w.Header().Set("Content-Type", "text/plain")
	}

	w.WriteHeader(resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read response body", http.StatusInternalServerError)
		log.Error().Err(err).Msg("Failed to read response body")
		return
	}

	if data.ReturnType == "raw" {
		if _, err := w.Write(body); err != nil {
			http.Error(w, "Failed to write response", http.StatusInternalServerError)
			log.Error().Err(err).Msg("Failed to write response")
		}
		log.Info().Msg("Response sent successfully")
		return
	}

	var response map[string]interface{}
	if err := json.Unmarshal(body, &response); err != nil {
		http.Error(w, "Failed to unmarshal response body", http.StatusInternalServerError)
		log.Error().Err(err).Msg("Failed to unmarshal response body")
		return
	}

	results, ok := response["results"].([]interface{})
	if !ok || len(results) == 0 {
		http.Error(w, "Invalid response format", http.StatusInternalServerError)
		log.Error().Msg("Invalid response format")
		return
	}

	result, ok := results[0].(map[string]interface{})
	if !ok {
		http.Error(w, "Invalid response format", http.StatusInternalServerError)
		log.Error().Msg("Invalid response format")
		return
	}

	stdout, ok := result["result"].(map[string]interface{})["stdout"].(string)
	if !ok {
		http.Error(w, "Invalid response format", http.StatusInternalServerError)
		log.Error().Msg("Invalid response format")
		return
	}

	// Check if the response is base64 encoded with content type
	if matched, _ := regexp.MatchString(`^data:([^;]+);base64,`, stdout); matched {
		parts := strings.SplitN(stdout, ",", 2)
		contentType := strings.TrimPrefix(strings.SplitN(parts[0], ":", 2)[1], "text/")
		contentType = strings.TrimSuffix(contentType, ";base64")

		w.Header().Set("Content-Type", contentType)

		decoded, err := base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			http.Error(w, "Failed to decode base64 response", http.StatusInternalServerError)
			log.Error().Err(err).Msg("Failed to decode base64 response")
			return
		}

		if _, err := w.Write(decoded); err != nil {
			http.Error(w, "Failed to write response", http.StatusInternalServerError)
			log.Error().Err(err).Msg("Failed to write response")
		}
	} else {
		if _, err := w.Write([]byte(stdout)); err != nil {
			http.Error(w, "Failed to write response", http.StatusInternalServerError)
			log.Error().Err(err).Msg("Failed to write response")
		}
	}
	log.Info().Msg("Response sent successfully")
}

func handleInsertHost(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	reqCount.WithLabelValues(r.URL.Path).Inc()
	defer func() {
		reqDuration.WithLabelValues(r.URL.Path).Observe(time.Since(start).Seconds())
	}()

	log.Info().Msg("Received insert host request")

	port := os.Getenv("PORT")
	if port == "" {
		port = "3010"
	}

	if r.Host != "localhost:"+port && r.Host != rootHost {
		handleRequest(w, r)
		return
	}

	var data HostData
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

	pattern := `^bafy[a-zA-Z0-9]{50,}$`
	matched, err := regexp.MatchString(pattern, data.Destination)
	if err != nil || !matched {
		http.Error(w, "Invalid destination format", http.StatusBadRequest)
		log.Error().Msg("Invalid destination format")
		return
	}

	// Check if the destination is unique
	existingData, err := getHostDataByDestination(data.Destination)
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

	rootURL := os.Getenv("ROOT_URL")
	if rootURL == "" {
		log.Fatal().Msg("ROOT_URL environment variable is required")
	}

	data.Host = nameGenerator.Generate() + "-" + data.Destination[len(data.Destination)-8:] + "." + rootURL
	data.Created = time.Now()
	data.Updated = time.Now()
	data.UpdaterID = ksuid.New().String()
	err = insertHostData(data)
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

func handleUpdateHost(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	reqCount.WithLabelValues(r.URL.Path).Inc()
	defer func() {
		reqDuration.WithLabelValues(r.URL.Path).Observe(time.Since(start).Seconds())
	}()

	log.Info().Msg("Received update host request")

	port := os.Getenv("PORT")
	if port == "" {
		port = "3010"
	}

	if r.Host != "localhost:"+port && r.Host != rootHost {
		handleRequest(w, r)
		return
	}

	var data HostData
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

	pattern := `^bafy[a-zA-Z0-9]{50,}$`
	matched, err := regexp.MatchString(pattern, data.Destination)
	if err != nil || !matched {
		http.Error(w, "Invalid destination format", http.StatusBadRequest)
		log.Error().Msg("Invalid destination format")
		return
	}

	existingData, err := getHostDataByHost(data.Host)
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
	err = updateHostData(data)
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

	port := os.Getenv("PORT")
	if port == "" {
		port = "3010"
	}

	if r.Host != "localhost:"+port && r.Host != rootHost {
		handleRequest(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(`{"status":"ok"}`)); err != nil {
		http.Error(w, "Failed to write response", http.StatusInternalServerError)
		log.Error().Err(err).Msg("Failed to write response")
		return
	}
	log.Info().Msg("Health check response sent successfully")
}

func startAPIServer() {
	http.HandleFunc("/", handleRequest)
	http.HandleFunc("/insert", handleInsertHost)
	http.HandleFunc("/update", handleUpdateHost)
	http.HandleFunc("/health", handleHealth)
	http.Handle("/metrics", promhttp.Handler())

	port := os.Getenv("PORT")
	if port == "" {
		port = "3010"
	}

	log.Info().Msgf("Server started on port %s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal().Err(err).Msg("Server failed")
	}
}
