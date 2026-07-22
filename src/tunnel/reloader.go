package tunnel

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/fsnotify/fsnotify"
	log "github.com/schollz/logger"
	"gopkg.in/yaml.v3"
)

type TunnelConfigEntry struct {
	Subdomain string `json:"subdomain"`
	LocalAddr string `json:"local_addr"`
	Type      string `json:"type"` // "http" or "tcp"
	Password  string `json:"password,omitempty"`
	Token     string `json:"token,omitempty"`
	HealthURL string `json:"health_url,omitempty"`
	MaxConns  int    `json:"max_conns,omitempty"`
}

type TunnelConfig struct {
	Tunnels []TunnelConfigEntry `json:"tunnels"`
}

// ConfigReloader watches a JSON config file and invokes a callback on changes.
// The callback is called with the new config — the caller decides what to do
// (e.g. add new tunnels, leave existing ones alone).
type ConfigReloader struct {
	path     string
	callback func(cfg *TunnelConfig)
	watcher  *fsnotify.Watcher
	stopCh   chan struct{}
	wg       sync.WaitGroup
}

// Call Start() to begin watching; Stop() to clean up.
func NewConfigReloader(path string, callback func(*TunnelConfig)) (*ConfigReloader, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("create fsnotify watcher: %w", err)
	}

	if err := watcher.Add(path); err != nil {
		watcher.Close()
		return nil, fmt.Errorf("watch %s: %w", path, err)
	}

	return &ConfigReloader{
		path:     path,
		callback: callback,
		watcher:  watcher,
		stopCh:   make(chan struct{}),
	}, nil
}

// Start begins watching the config file. The callback is invoked immediately
// with the current config, then again on each file change.
func (r *ConfigReloader) Start() error {
	// Initial load
	cfg, err := r.load()
	if err != nil {
		return fmt.Errorf("initial config load: %w", err)
	}
	r.callback(cfg)

	r.wg.Add(1)
	go r.loop()
	return nil
}

func (r *ConfigReloader) Stop() {
	close(r.stopCh)
	r.watcher.Close()
	r.wg.Wait()
}

func (r *ConfigReloader) loop() {
	defer r.wg.Done()

	for {
		select {
		case event, ok := <-r.watcher.Events:
			if !ok {
				return
			}
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
				// Debounce — reload once
				cfg, err := r.load()
				if err != nil {
					log.Errorf("reload config %s: %v", r.path, err)
					continue
				}
				log.Infof("config reloaded: %s", r.path)
				r.callback(cfg)
			}

		case err, ok := <-r.watcher.Errors:
			if !ok {
				return
			}
			log.Errorf("config watcher error: %v", err)

		case <-r.stopCh:
			return
		}
	}
}

func (r *ConfigReloader) load() (*TunnelConfig, error) {
	data, err := os.ReadFile(r.path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", r.path, err)
	}

	var cfg TunnelConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse JSON: %w", err)
	}

	return &cfg, nil
}

// YAMLConfigWatcher watches a YAML tunnel config file for changes
// and calls a callback on each change with the parsed result.
type YAMLConfigWatcher struct {
	path     string
	callback func(*ConfigFile)
	watcher  *fsnotify.Watcher
	stopCh   chan struct{}
	wg       sync.WaitGroup
}

// The callback is invoked immediately with the current config, then on each file change.
func NewYAMLConfigWatcher(path string, callback func(*ConfigFile)) (*YAMLConfigWatcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("create fsnotify watcher: %w", err)
	}

	if err := watcher.Add(path); err != nil {
		watcher.Close()
		return nil, fmt.Errorf("watch %s: %w", path, err)
	}

	w := &YAMLConfigWatcher{
		path:     path,
		callback: callback,
		watcher:  watcher,
		stopCh:   make(chan struct{}),
	}

	// Initial load
	cfg, err := w.loadYAML()
	if err != nil {
		log.Warnf("initial YAML config load: %v", err)
	} else {
		w.callback(cfg)
	}

	return w, nil
}

func (w *YAMLConfigWatcher) Start() {
	w.wg.Add(1)
	go w.loop()
}

func (w *YAMLConfigWatcher) Stop() {
	close(w.stopCh)
	w.watcher.Close()
	w.wg.Wait()
}

func (w *YAMLConfigWatcher) loop() {
	defer w.wg.Done()

	for {
		select {
		case event, ok := <-w.watcher.Events:
			if !ok {
				return
			}
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
				cfg, err := w.loadYAML()
				if err != nil {
					log.Errorf("reload YAML config %s: %v", w.path, err)
					continue
				}
				log.Infof("YAML config reloaded: %s", w.path)
				w.callback(cfg)
			}

		case err, ok := <-w.watcher.Errors:
			if !ok {
				return
			}
			log.Errorf("YAML config watcher error: %v", err)

		case <-w.stopCh:
			return
		}
	}
}

func (w *YAMLConfigWatcher) loadYAML() (*ConfigFile, error) {
	data, err := os.ReadFile(w.path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", w.path, err)
	}

	var cfg ConfigFile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse YAML: %w", err)
	}

	return &cfg, nil
}
