package pkg

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

const testPath = "./tests"

var configFile = filepath.Join(testPath, "goma.yml")

func TestInit(t *testing.T) {
	err := os.MkdirAll(testPath, os.ModePerm)
	if err != nil {
		t.Error(err)
	}
}

func TestStart(t *testing.T) {
	TestInit(t)
	initConfig(configFile)
	g := GatewayServer{}
	gatewayServer, err := g.Config(configFile)
	if err != nil {
		t.Error(err)
	}
	route := gatewayServer.Initialize()
	route.HandleFunc("/", func(rw http.ResponseWriter, r *http.Request) {
		_, err := rw.Write([]byte("Hello Goma Proxy"))
		if err != nil {
			t.Fatalf("Failed writing HTTP response: %v", err)
		}
	})
	assertResponseBody := func(t *testing.T, s *httptest.Server, expectedBody string) {
		resp, err := s.Client().Get(s.URL)
		if err != nil {
			t.Fatalf("unexpected error getting from server: %v", err)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("expected a status code of 200, got %v", resp.StatusCode)
		}
	}
	t.Run("httpServer", func(t *testing.T) {
		s := httptest.NewServer(route)
		defer s.Close()
		assertResponseBody(t, s, "Hello Goma Proxy")
	})

}
