package internal

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const testPath = "./tests"
const extraRoutePath = "./tests/extra"
const serverURL = "http://localhost:8080"

var configFile = filepath.Join(testPath, "goma.yml")
var configFile2 = filepath.Join(testPath, "goma2.yml")

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
	err := initConfig(configFile2)
	if err != nil {
		t.Fatal("Error init config:", err)
	}
	err = initTestConfig(configFile)
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
	err := initTestConfig(configFile)
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
	log.Println("Wait...")
	time.Sleep(5 * time.Second) // Sleep for 5 seconds

	resp, err := makeRequest("http://localhost:8080/readyz")
	if err != nil {
		t.Fatalf("Error making request: %s", err.Error())
	}
	assertResponse(t, resp, http.StatusOK)

	testBasicAuthRequest(t)

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

func testBasicAuthRequest(t *testing.T) {
	// Create a request to the mock server
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/api", serverURL), nil)
	if err != nil {
		t.Fatalf("Error creating request: %v", err)
	}

	// Add Basic Auth header
	auth := "admin:admin"
	basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
	req.Header.Add("Authorization", basicAuth)

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Error sending request: %v", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			t.Error("Error closing body")
		}
	}(resp.Body)

	// Check the response status
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status code %d, got %d", http.StatusNotFound, resp.StatusCode)
	}
}
