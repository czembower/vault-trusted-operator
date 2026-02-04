// http_client.go
package main

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"
	"vault-trusted-operator/config"
)

func NewHTTPClient(cfg config.Config) *http.Client {
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   cfg.ClientTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   cfg.ClientTimeout,
		ResponseHeaderTimeout: cfg.ClientTimeout,
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       60 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.InsecureTLS, // intentional; controlled by config
		},
	}
	return &http.Client{
		Transport: tr,
		Timeout:   cfg.ClientTimeout,
	}
}
