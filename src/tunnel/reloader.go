package tunnel

import (
	"fmt"
	"os"
	"sync"

	"github.com/fsnotify/fsnotify"
	log "github.com/schollz/logger"
	"gopkg.in/yaml.v3"
)

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
