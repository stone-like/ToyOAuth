package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

var client = new(http.Client)

func TestHttp(t *testing.T) {
	router := gin.Default()
	SetSession(router)
	SetRoute(router)
	testServer := httptest.NewServer(router)
	defer testServer.Close()

	req, _ := http.NewRequest("GET", testServer.URL+"/auth?state=xyz&clientId=1&redirectUri=http://localhost:8080/auth&responseType=code&scope=AAA%20BBB", nil)

	resp, _ := client.Do(req)
	parser := &http.Request{Header: http.Header{"Cookie": resp.Header.Values("Set-Cookie")}}
	cookie, _ := parser.Cookie("mysession")
	io.ReadAll(resp.Body)

	val := url.Values{}
	val.Add("login_name", "test")
	val.Add("password", "test")
	val.Add("approved", "true")

	req, _ = http.NewRequest("POST", testServer.URL+"/decision", strings.NewReader(val.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{
		Name:  cookie.Name,
		Value: cookie.Value,
	})

	resp, _ = client.Do(req)
	io.ReadAll(resp.Body)
}
