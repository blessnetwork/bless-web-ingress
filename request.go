package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"

	"github.com/rs/zerolog/log"
)

func makeParallelRequests(urls []string, jsonData []byte) (*http.Response, []byte, error) {
	type result struct {
		resp *http.Response
		body []byte
		err  error
	}

	ch := make(chan result, len(urls))

	for _, url := range urls {
		go func(url string) {
			resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
			if err != nil {
				ch <- result{nil, nil, err}
				return
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			ch <- result{resp, body, err}
		}(url)
	}

	var lastErr error
	for i := 0; i < len(urls); i++ {
		res := <-ch
		if res.err != nil {
			lastErr = res.err
			continue
		}
		if res.resp.StatusCode == http.StatusOK {
			return res.resp, res.body, nil
		}
		lastErr = fmt.Errorf("received status code %d", res.resp.StatusCode)
	}

	return nil, nil, lastErr
}

func makeFallbackRequest(urls []string, jsonData []byte) (*http.Response, []byte, error) {
	var lastErr error

	for _, url := range urls {
		resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
		if err != nil {
			lastErr = err
			log.Error().Err(err).Str("url", url).Msg("Request failed, trying next URL")
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = err
			log.Error().Err(err).Str("url", url).Msg("Failed to read response body, trying next URL")
			continue
		}

		if resp.StatusCode == http.StatusOK {
			return resp, body, nil
		}

		lastErr = fmt.Errorf("received status code %d from %s", resp.StatusCode, url)
		log.Error().Err(lastErr).Str("url", url).Msg("Request returned non-OK status, trying next URL")
	}

	return nil, nil, lastErr
}
