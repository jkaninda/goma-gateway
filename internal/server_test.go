package pkg

import (
	"context"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

const testPath = "./tests"
const extraRoutePath = "./tests/extra"

var configFile = filepath.Join(testPath, "goma.yml")

func TestInit(t *testing.T) {
	err := os.MkdirAll(testPath, os.ModePerm)
	if err != nil {
		t.Error(err)
	}
	err = os.MkdirAll(extraRoutePath, os.ModePerm)
	if err != nil {
		t.Error(err)
	}
}

func TestCheckConfig(t *testing.T) {
	TestInit(t)
	err := initConfiguration(configFile)
	if err != nil {
		t.Fatal("Error init config:", err)
	}
	err = CheckConfig(configFile)
	if err != nil {
		t.Fatalf("Error checking config: %s", err.Error())
	}
	log.Println("Goma Gateway configuration file checked successfully")
}

func TestStart(t *testing.T) {
	TestInit(t)
	err := initConfiguration(configFile)
	if err != nil {
		t.Fatalf("Error initializing config: %s", err.Error())
	}

	err = initExtraRoute(extraRoutePath)
	if err != nil {
		t.Fatalf("Error creating extra routes file: %s", err.Error())
	}
	ctx := context.Background()
	g := GatewayServer{}
	gatewayServer, err := g.Config(configFile, ctx)
	if err != nil {
		t.Error(err)
	}
	route := gatewayServer.Initialize()
	assertResponseBody := func(t *testing.T, s *httptest.Server) {
		resp, err := s.Client().Get(s.URL + "/health/live")
		if err != nil {
			t.Fatalf("unexpected error getting from server: %v", err)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("expected a status code of 200, got %v", resp.StatusCode)
		}
	}
	go func() {
		err = gatewayServer.Start()
		if err != nil {
			t.Error(err)
			return
		}
	}()

	t.Run("httpServer", func(t *testing.T) {
		s := httptest.NewServer(route)
		defer s.Close()
		assertResponseBody(t, s)
	})
	ctx.Done()
}
