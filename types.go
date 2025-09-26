package main

import "time"

type ExecutionResult struct {
	Result struct {
		Stdout   string `json:"stdout"`
		Stderr   string `json:"stderr"`
		ExitCode int    `json:"exit_code"`
	} `json:"result"`
	Peers     []string `json:"peers"`
	Frequency int      `json:"frequency"`
}

type APIResponse struct {
	Cluster struct {
		Peers []string `json:"peers"`
	} `json:"cluster"`
	Code      string            `json:"code"`
	RequestID string            `json:"request_id"`
	Results   []ExecutionResult `json:"results"`
}

type CacheEntry struct {
	ContentType string
	Data        []byte
	Timestamp   time.Time
}
