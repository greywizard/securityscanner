package main

import (
	"fmt"
	"io"
	"net/http"
	"time"
  
	"github.com/pressly/chi"
	"github.com/goware/throttler"
)

// handler is a slow / hard working handler that finishes in 2 seconds.
func handler(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, "This takes it to a whole....nutha...\n")
  
	if fl, ok := w.(http.Flusher); ok { fl.Flush() }
  
	time.Sleep(2 * time.Second)
	io.WriteString(w, "...level!\n")
}

func main() {
	r := chi.NewRouter()
  
	// Limit to 5 requests globally.
	r.Use(throttler.Limit(5))
	r.Get("/*", handler)

	admin := chi.NewRouter()
	// Limit to 2 requests for admin route
	admin.Use(throttler.Limit(2))
	admin.Get("/", handler)
	
	r.Mount("/admin/", admin)

	fmt.Printf("Try running the following commands (in different terminal):\n\n")
	fmt.Printf("for i in `seq 1 10`; do (curl 127.0.0.1:8000/ &); done\n\n")
	fmt.Printf("for i in `seq 1 10`; do (curl 127.0.0.1:8000/admin/ &); done\n\n")
  
	http.ListenAndServe(":8000", r)
}
