package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/joho/godotenv"
)

type Verify struct {
	Success  bool
	Hostname string
}

func checkHostname(hostname string) bool {
	allowed := strings.Split(os.Getenv("ALLOWED_HOSTS"), ",")
	for _, h := range allowed {
		if strings.Contains(hostname, h) {
			return true
		}
	}
	return false
}

func enableCors(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
	(*w).Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
}

func handler(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

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

		if verify.Success && checkHostname(verify.Hostname) {
			path := r.URL.Path

			upstreamURL := os.Getenv("UPSTREAM_URL") + path

			client := &http.Client{}
			ureq, err := http.NewRequest("GET", upstreamURL, nil)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}

			ureq.Header.Add("X-Forwarded-For", ip)
			upstream, err := client.Do(ureq)
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
	godotenv.Load()

	http.HandleFunc("/", handler)
	http.ListenAndServe(":8080", nil)
}
