package main

import (
	"crypto/tls"
	"net/http"
)

func client() *http.Client {
	// ruleid: openasy.go.tls-verification-off
	cfg := &tls.Config{InsecureSkipVerify: true}
	other := &tls.Config{}
	// ruleid: openasy.go.tls-verification-off
	other.InsecureSkipVerify = true
	// ok: openasy.go.tls-verification-off
	safe := &tls.Config{MinVersion: tls.VersionTLS12}
	_ = safe
	_ = other
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
}
