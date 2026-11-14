package lake

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

// Delivery is one request a ledger view answered (replay-harness.md §2.5): time offset, view, object key or
// method, the ledgers the response carried, bytes and status.
type Delivery struct {
	TMS     int64    `json:"t_ms"`
	View    string   `json:"view"`             // rpc, s3
	Method  string   `json:"method,omitempty"` // JSON-RPC method, or the HTTP method for s3
	Key     string   `json:"key,omitempty"`    // object key (s3)
	Query   string   `json:"query,omitempty"`  // request query (s3), for example list-type=2&prefix=…
	Ledgers []uint32 `json:"ledgers,omitempty"`
	Bytes   int64    `json:"bytes"`
	Status  string   `json:"status"` // "ok", "error <code>", or an HTTP status code
}

// DeliveryLog records deliveries, appends them as NDJSON to an optional writer, and remembers which ledgers
// were delivered. It is safe for concurrent use.
type DeliveryLog struct {
	mu      sync.Mutex
	start   time.Time
	w       io.Writer
	enc     *json.Encoder
	records []Delivery
	served  map[uint32]bool
}

// NewDeliveryLog starts a log; w may be nil.
func NewDeliveryLog(w io.Writer) *DeliveryLog {
	d := &DeliveryLog{start: time.Now(), w: w, served: map[uint32]bool{}}
	if w != nil {
		d.enc = json.NewEncoder(w)
	}
	return d
}

// Add stamps and records one delivery. Ledgers count as served only when the status is "ok" or 200.
func (d *DeliveryLog) Add(rec Delivery) {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	rec.TMS = time.Since(d.start).Milliseconds()
	d.records = append(d.records, rec)
	if rec.Status == "ok" || rec.Status == "200" {
		for _, s := range rec.Ledgers {
			d.served[s] = true
		}
	}
	if d.enc != nil {
		d.enc.Encode(rec)
	}
}

// Records returns a copy of every delivery so far.
func (d *DeliveryLog) Records() []Delivery {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]Delivery(nil), d.records...)
}

// Served reports whether a ledger was delivered successfully at least once.
func (d *DeliveryLog) Served(seq uint32) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.served[seq]
}
