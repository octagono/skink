package tunnel

import (
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	log "github.com/schollz/logger"
)

// HealthChecker periodically checks if tunnels' local services are reachable.
// Unhealthy tunnels are reported via the callback but NOT automatically
// unregistered (the operator can decide).
type HealthChecker struct {
	registry    *Registry
	interval    time.Duration
	onUnhealthy func(entry *TunnelEntry)
	stopCh      chan struct{}
	wg          sync.WaitGroup
}

// interval is how often to check (default 60s).
// onUnhealthy is called when a tunnel's local service is unreachable.
func NewHealthChecker(registry *Registry, interval time.Duration, onUnhealthy func(*TunnelEntry)) *HealthChecker {
	if interval == 0 {
		interval = 60 * time.Second
	}
	return &HealthChecker{
		registry:    registry,
		interval:    interval,
		onUnhealthy: onUnhealthy,
		stopCh:      make(chan struct{}),
	}
}

func (h *HealthChecker) Start() {
	h.wg.Add(1)
	go h.loop()
}

func (h *HealthChecker) Stop() {
	close(h.stopCh)
	h.wg.Wait()
}

func (h *HealthChecker) loop() {
	defer h.wg.Done()

	ticker := time.NewTicker(h.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			h.checkAll()
		case <-h.stopCh:
			return
		}
	}
}

func (h *HealthChecker) checkAll() {
	entries := h.registry.List()
	for _, entry := range entries {
		go h.checkOne(entry)
	}
}

// checkOne performs a single health check on a tunnel.
// For HTTP tunnels with HealthURL set, does an HTTP GET.
// Otherwise does a TCP dial to the local address.
func (h *HealthChecker) checkOne(entry *TunnelEntry) {
	var err error

	if entry.HealthURL != "" {
		err = h.checkHTTP(entry.HealthURL)
	} else {
		err = h.checkTCP(entry.LocalAddr)
	}

	if err != nil {
		log.Debugf("health check failed for %s: %v", entry.Subdomain, err)
		if h.onUnhealthy != nil {
			h.onUnhealthy(entry)
		}
	}
}

func (h *HealthChecker) checkTCP(addr string) error {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("tcp dial %s: %w", addr, err)
	}
	conn.Close()
	return nil
}

func (h *HealthChecker) checkHTTP(url string) error {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("http get %s: %w", url, err)
	}
	resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return nil
	}
	return fmt.Errorf("http %s returned status %d", url, resp.StatusCode)
}
