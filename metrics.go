package main

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	reqCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Number of HTTP requests",
		},
		[]string{"path"},
	)
	reqDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "Duration of HTTP requests",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"path"},
	)
	deployCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "total_deployments",
			Help: "Total number of deployments",
		},
	)
	updateCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "total_updates",
			Help: "Total number of updates",
		},
	)
)

func registerMetrics() {
	prometheus.MustRegister(reqCount)
	prometheus.MustRegister(reqDuration)
	prometheus.MustRegister(deployCount)
	prometheus.MustRegister(updateCount)
}
