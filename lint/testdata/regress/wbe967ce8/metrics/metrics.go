// Package metrics stands in for wallet-backend's internal/metrics at commit
// e967ce8: the histogram contract_deploy.go observes.
package metrics

// Observer records one observation.
type Observer interface{ Observe(float64) }

// HistogramVec hands out an observer per label set.
type HistogramVec struct{}

type nop struct{}

func (nop) Observe(float64) {}

// WithLabelValues returns the observer for the labels.
func (*HistogramVec) WithLabelValues(...string) Observer { return nop{} }

// IngestionMetrics holds the ingestion histograms.
type IngestionMetrics struct {
	StateChangeProcessingDuration *HistogramVec
}
