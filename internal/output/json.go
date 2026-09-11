package output

import (
	"encoding/json"
	"io"
	"sync"

	"github.com/pranavrav09/RuntimeLens/internal/events"
)

type JSONWriter struct {
	encoder *json.Encoder
	mu      sync.Mutex
}

func NewJSONWriter(w io.Writer) *JSONWriter {
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)

	return &JSONWriter{encoder: encoder}
}

func (w *JSONWriter) WriteAlert(alert events.Alert) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.encoder.Encode(alert)
}

func (w *JSONWriter) WriteEvent(event events.Event) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.encoder.Encode(event)
}
