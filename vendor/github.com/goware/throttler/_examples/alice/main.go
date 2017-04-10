package main

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/justinas/alice"

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
	handlerFunc := http.HandlerFunc(handler)
	chain := alice.New(throttler.Limit(5)).Then(handlerFunc)

	fmt.Printf("Try running the following commands (in different terminal):\n\n")
	fmt.Printf("for i in `seq 1 10`; do (curl 127.0.0.1:8000/ &); done\n\n")

	http.ListenAndServe(":8000", chain)
}
