package tunnel

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Metrics tracks tunnel server statistics and exposes them via Prometheus format.
type Metrics struct {
	mu       sync.Mutex
	registry *Registry

	// Counters
	totalTunnelsRegistered   int64
	totalTunnelsUnregistered int64
	totalProxyRequests       int64
	totalProxyErrors         int64
	totalBytesIn             int64
	totalBytesOut            int64

	// Gauges
	activeTunnels int
	activeProxies int

	// Histograms (simplified — just sums and counts for averaging)
	proxyRequestCount int
	proxyRequestSum   time.Duration

	startTime time.Time
}

func NewMetrics() *Metrics {
	return &Metrics{
		startTime: time.Now(),
	}
}

// SetRegistry wires the registry so the Prometheus endpoint can enumerate tunnels.
func (m *Metrics) SetRegistry(r *Registry) {
	m.mu.Lock()
	m.registry = r
	m.mu.Unlock()
}

func (m *Metrics) RecordTunnelRegistered() {
	m.mu.Lock()
	m.totalTunnelsRegistered++
	m.activeTunnels++
	m.mu.Unlock()
}

func (m *Metrics) RecordTunnelUnregistered() {
	m.mu.Lock()
	m.totalTunnelsUnregistered++
	if m.activeTunnels > 0 {
		m.activeTunnels--
	}
	m.mu.Unlock()
}

func (m *Metrics) RecordProxyRequest(duration time.Duration, err bool) {
	m.mu.Lock()
	m.totalProxyRequests++
	if err {
		m.totalProxyErrors++
	} else {
		m.proxyRequestCount++
		m.proxyRequestSum += duration
	}
	m.mu.Unlock()
}

func (m *Metrics) RecordProxyStart() {
	m.mu.Lock()
	m.activeProxies++
	m.mu.Unlock()
}

func (m *Metrics) RecordProxyEnd() {
	m.mu.Lock()
	if m.activeProxies > 0 {
		m.activeProxies--
	}
	m.mu.Unlock()
}

func (m *Metrics) RecordBytes(in, out int64) {
	m.mu.Lock()
	m.totalBytesIn += in
	m.totalBytesOut += out
	m.mu.Unlock()
}

type MetricsSnapshot struct {
	TotalTunnelsRegistered   int64
	TotalTunnelsUnregistered int64
	TotalProxyRequests       int64
	TotalProxyErrors         int64
	TotalBytesIn             int64
	TotalBytesOut            int64
	ActiveTunnels            int
	ActiveProxies            int
	AvgProxyDuration         time.Duration
	Uptime                   time.Duration
}

func (m *Metrics) Snapshot() MetricsSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()

	var avg time.Duration
	if m.proxyRequestCount > 0 {
		avg = m.proxyRequestSum / time.Duration(m.proxyRequestCount)
	}

	return MetricsSnapshot{
		TotalTunnelsRegistered:   m.totalTunnelsRegistered,
		TotalTunnelsUnregistered: m.totalTunnelsUnregistered,
		TotalProxyRequests:       m.totalProxyRequests,
		TotalProxyErrors:         m.totalProxyErrors,
		TotalBytesIn:             m.totalBytesIn,
		TotalBytesOut:            m.totalBytesOut,
		ActiveTunnels:            m.activeTunnels,
		ActiveProxies:            m.activeProxies,
		AvgProxyDuration:         avg,
		Uptime:                   time.Since(m.startTime),
	}
}

// PrometheusHandler returns an http.HandlerFunc that exposes metrics in Prometheus format.
func (m *Metrics) PrometheusHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s := m.Snapshot()

		// Per-tunnel stats
		var tunnelsStats string
		if reg := m.registry; reg != nil {
			for _, entry := range reg.List() {
				stats := entry.Stats()
				tunnelsStats += fmt.Sprintf(
					"tunnel_active_conns{tunnel_id=\"%s\",subdomain=\"%s\"} %d\n"+
						"tunnel_total_conns{tunnel_id=\"%s\",subdomain=\"%s\"} %d\n"+
						"tunnel_bytes_in{tunnel_id=\"%s\",subdomain=\"%s\"} %d\n"+
						"tunnel_bytes_out{tunnel_id=\"%s\",subdomain=\"%s\"} %d\n",
					entry.ID, entry.Subdomain, stats.ActiveConns,
					entry.ID, entry.Subdomain, stats.TotalConns,
					entry.ID, entry.Subdomain, stats.TotalBytesIn,
					entry.ID, entry.Subdomain, stats.TotalBytesOut,
				)
			}
		}

		response := fmt.Sprintf(
			"# TYPE tunnel_total_registered counter\n"+
				"tunnel_total_registered %d\n"+
				"# TYPE tunnel_total_unregistered counter\n"+
				"tunnel_total_unregistered %d\n"+
				"# TYPE tunnel_active gauge\n"+
				"tunnel_active %d\n"+
				"# TYPE tunnel_proxy_requests_total counter\n"+
				"tunnel_proxy_requests_total %d\n"+
				"# TYPE tunnel_proxy_errors_total counter\n"+
				"tunnel_proxy_errors_total %d\n"+
				"# TYPE tunnel_proxy_active gauge\n"+
				"tunnel_proxy_active %d\n"+
				"# TYPE tunnel_bytes_in_total counter\n"+
				"tunnel_bytes_in_total %d\n"+
				"# TYPE tunnel_bytes_out_total counter\n"+
				"tunnel_bytes_out_total %d\n"+
				"# TYPE tunnel_uptime_seconds gauge\n"+
				"tunnel_uptime_seconds %d\n"+
				"%s",
			s.TotalTunnelsRegistered,
			s.TotalTunnelsUnregistered,
			s.ActiveTunnels,
			s.TotalProxyRequests,
			s.TotalProxyErrors,
			s.ActiveProxies,
			s.TotalBytesIn,
			s.TotalBytesOut,
			int64(s.Uptime.Seconds()),
			tunnelsStats,
		)

		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprint(w, response)
	}
}
