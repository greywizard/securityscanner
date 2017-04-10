package throttler

import "net/http"

// throttler is a HTTP middleware that limits number of
// currently processed requests at the same time.
type throttler struct {
	h     http.Handler
	limit chan struct{}
}

// ServeHTTP implements the http.Handler interface.
func (t *throttler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t.limit <- struct{}{}
	defer func() { <-t.limit }()
	t.h.ServeHTTP(w, r)
}

// Limit create new throttler middleware with a specified limit.
func Limit(limit int) func(http.Handler) http.Handler {
	t := throttler{
		limit: make(chan struct{}, limit),
	}
	return func(h http.Handler) http.Handler {
		t.h = h
		return &t
	}
}
