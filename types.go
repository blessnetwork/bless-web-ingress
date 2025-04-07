package main

import "time"

type HostData struct {
	Host              string    `json:"host"`
	Destination       string    `json:"destination"`
	Owner             string    `json:"owner"`
	Created           time.Time `json:"created"`
	Updated           time.Time `json:"updated"`
	UpdaterID         string    `json:"updater_id"`
	EntryMethod       string    `json:"entry_method"`
	ReturnType        string    `json:"return_type"`
	Permissions       []string  `json:"permissions"` // Array of permission strings
	PermissionsString string    `json:"-"`           // Storage format for database (not exposed in JSON)
}
