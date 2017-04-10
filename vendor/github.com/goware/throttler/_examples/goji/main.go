package main

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/zenazn/goji"
	"github.com/zenazn/goji/web"

	"github.com/goware/throttler"
)

// handler is slow / hard working handler that finishes in 2 seconds.
func handler(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, "This is going to be legen... (wait for it)\n")
	if fl, ok := w.(http.Flusher); ok {
		fl.Flush()
	}
	time.Sleep(2 * time.Second)
	io.WriteString(w, "...dary!\n")
}

func main() {
	// Limit to 5 requests globally.
	goji.Use(throttler.Limit(5))

	// Limit /admin route to 2 requests.
	admin := web.New()
	admin.Use(throttler.Limit(2))
	admin.Get("/*", handler)

	goji.Handle("/admin/*", admin)
	goji.Get("/*", handler)

	fmt.Printf("Try running the following commands (in different terminal):\n\n")
	fmt.Printf("for i in `seq 1 10`; do (curl 127.0.0.1:8000/ &); done\n\n")
	fmt.Printf("for i in `seq 1 10`; do (curl 127.0.0.1:8000/admin/ &); done\n\n")

	goji.Serve()
}
