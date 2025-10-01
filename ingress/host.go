package ingress

import (
	"time"
)

type Host struct {
	Host              string    `json:"host"`
	Destination       string    `json:"destination"`
	Owner             string    `json:"owner"` // XXX: Owner field is not set by us?
	Created           time.Time `json:"created"`
	Updated           time.Time `json:"updated"`
	UpdaterID         string    `json:"updater_id"`
	EntryMethod       string    `json:"entry_method"`
	ReturnType        string    `json:"return_type"`
	PermissionsString string    `json:"-"` // Storage format for database (not exposed in JSON)

	// Fields NOT saved to DB.
	NumberOfNodes int      `json:"number_of_nodes"`
	Permissions   []string `json:"permissions"` // Array of permission strings
}
