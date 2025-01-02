package internal

import (
	"context"
	"log"
	"net/http"
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
	err := initConfig(configFile)
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
	err := initConfig(configFile)
	if err != nil {
		t.Fatalf("Error initializing config: %s", err.Error())
	}

	err = initExtraRoute(extraRoutePath)
	if err != nil {
		t.Fatalf("Error creating extra routes file: %s", err.Error())
	}
	err = CheckConfig(configFile)
	if err != nil {
		t.Fatalf("Error checking config: %s", err.Error())
	}
	ctx := context.Background()
	g := GatewayServer{}
	gatewayServer, err := g.Config(configFile, ctx)
	if err != nil {
		t.Error(err)
	}
	err = gatewayServer.Initialize()
	if err != nil {
		return
	}
	go func() {
		err = gatewayServer.Start()
		if err != nil {
			t.Error(err)
			return
		}
	}()

	// Test health check

	resp, err := makeRequest("http://localhost:8080/readyz")
	if err != nil {
		t.Fatalf("Error making request: %s", err.Error())
	}
	assertResponse(t, resp, http.StatusOK)

	ctx.Done()
}

func assertResponse(t *testing.T, resp *http.Response, status int) {
	// assert response
	if resp.StatusCode != status {
		t.Fatalf("expected status code %d, got %d", status, resp.StatusCode)
	}
	log.Println("Response status code:", resp.StatusCode)
}

func makeRequest(url string) (*http.Response, error) {
	response, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	return response, nil
}
