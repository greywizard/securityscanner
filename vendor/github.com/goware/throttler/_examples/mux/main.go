package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

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
	limit5 := throttler.Limit(5)
	limit2 := throttler.Limit(2)

	handlerFunc := http.HandlerFunc(handler)
	http.Handle("/limit/5", limit5(handlerFunc))
	http.Handle("/limit/2", limit2(handlerFunc))

	fmt.Printf("Try running the following commands (in different terminal):\n\n")
	fmt.Printf("for i in `seq 1 10`; do (curl 127.0.0.1:8000/limit/5 &); done\n\n")
	fmt.Printf("for i in `seq 1 10`; do (curl 127.0.0.1:8000/limit/2 &); done\n\n")

	log.Fatal(http.ListenAndServe(":8000", nil))
}
