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

var configFile = filepath.Join(testPath, "goma.yml")

func TestInit(t *testing.T) {
	err := os.MkdirAll(testPath, os.ModePerm)
	if err != nil {
		t.Error(err)
	}
}

func TestCheckConfig(t *testing.T) {
	TestInit(t)
	err := initConfig(configFile)
	if err != nil {
		t.Fatalf(err.Error())
	}
	err = CheckConfig(configFile)
	if err != nil {
		t.Fatalf(err.Error())
	}
	log.Println("Goma Gateway configuration file checked successfully")
}

func TestStart(t *testing.T) {
	TestInit(t)
	err := initConfig(configFile)
	if err != nil {
		t.Fatalf(err.Error())
	}
	g := GatewayServer{}
	gatewayServer, err := g.Config(configFile)
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
	ctx := context.Background()
	go func() {
		err = gatewayServer.Start(ctx)
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
