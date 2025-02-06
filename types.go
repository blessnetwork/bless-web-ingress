package main

import "time"

type HostData struct {
	Host        string    `json:"host"`
	Destination string    `json:"destination"`
	Owner       string    `json:"owner"`
	Created     time.Time `json:"created"`
	Updated     time.Time `json:"updated"`
	UpdaterID   string    `json:"updater_id,omitempty"`
	EntryMethod string    `json:"entry_method"`          // New field
	ReturnType  string    `json:"return_type,omitempty"` // New field
}
