/*
 * Copyright 2024 Jonas Kaninda
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

var ConfigAcme *AcmeServer

type AcmeServer struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
	client       *lego.Client
}

func (u AcmeServer) GetEmail() string {
	return u.Email
}

func (u AcmeServer) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u AcmeServer) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func (u AcmeServer) GenCert(domain string) (*certificate.Resource, error) {
	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}
	certificates, err := u.client.Certificate.Obtain(request)
	if err != nil {
		return nil, err
	}
	return certificates, nil
}

func StartAcmeServer(email, httpPort string) error {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	acmeSer := &AcmeServer{
		Email: email,
		key:   privateKey,
	}
	config := lego.NewConfig(acmeSer)
	//
	config.CADirURL = lego.LEDirectoryProduction
	config.Certificate.KeyType = certcrypto.RSA2048
	// Create a new client
	client, err := lego.NewClient(config)
	if err != nil {
		return err
	}
	// Set up an HTTP01 provider on port 80
	err = client.Challenge.SetHTTP01Provider(http01.NewProviderServer("", httpPort))
	if err != nil {
		return err
	}
	// Register the user
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return err
	}
	acmeSer.client = client
	acmeSer.Registration = reg
	ConfigAcme = acmeSer
	return nil
}
