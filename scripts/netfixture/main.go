// netfixture is an HTTP endpoint for disposable container network tests.
package main

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

func main() {
	server := &http.Server{Addr: ":8080", ReadHeaderTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintln(w, r.RemoteAddr)
	})}
	log.Fatal(server.ListenAndServe())
}
