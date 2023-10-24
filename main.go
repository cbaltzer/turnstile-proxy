package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Verify struct {
	Success bool
}

func handler(w http.ResponseWriter, r *http.Request) {

	token := r.URL.Query().Get("token")
	ip := r.Header.Get("CF-Connecting-IP")

	if ip == "" {
		ip = r.RemoteAddr
	}

	if token == "" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	} else {

		secret := os.Getenv("SECRET_KEY")

		form := url.Values{
			"secret":   {secret},
			"response": {token},
			"remoteip": {ip},
		}

		verifyRes, err := http.PostForm(os.Getenv("VERIFY_URL"), form)
		if err != nil || verifyRes.StatusCode != http.StatusOK {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		defer verifyRes.Body.Close()

		var verify Verify
		err = json.NewDecoder(verifyRes.Body).Decode(&verify)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if verify.Success {
			path := r.URL.Path

			upstreamURL := os.Getenv("UPSTREAM_URL") + path

			fmt.Println(upstreamURL)

			upstream, err := http.Get(upstreamURL)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}

			w.WriteHeader(upstream.StatusCode)
			_, _ = io.Copy(w, upstream.Body)
		} else {
			http.Error(w, "Forbidden", http.StatusForbidden)
		}

	}
}

func main() {
	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/", handler)

	http.ListenAndServe(":8080", nil)
}
