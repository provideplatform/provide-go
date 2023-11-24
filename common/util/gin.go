/*
 * Copyright 2017-2022 Provide Technologies Inc.
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
 */

package util

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"

	selfsignedcert "github.com/kthomas/go-self-signed-cert"
	uuid "github.com/kthomas/go.uuid"
	common "github.com/provideplatform/provide-go/common"
)

// gin configuration vars
var (
	// ListenAddr is the http server listen address
	ListenAddr string

	// ListenPort is the http server listen port
	ListenPort string

	// CertificatePath is the SSL certificate path used by HTTPS listener
	CertificatePath string

	// PrivateKeyPath is the private key path used by HTTPS listener
	PrivateKeyPath string

	// ServeTLS is true when CertificatePath and PrivateKeyPath are valid
	ServeTLS bool
)

// RequireGin initializes the gin configuration
func RequireGin() {
	ListenAddr = os.Getenv("LISTEN_ADDR")
	if ListenAddr == "" {
		ListenPort = os.Getenv("PORT")
		if ListenPort == "" {
			ListenPort = "8080"
		}
		ListenAddr = fmt.Sprintf("0.0.0.0:%s", ListenPort)
	}

	requireTLSConfiguration()
}

// TrackAPICalls returns gin middleware for tracking API calls
func TrackAPICalls() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			var subject string
			orgID := AuthorizedSubjectID(c, "organization")
			if orgID != nil {
				subject = fmt.Sprintf("organization:%s", orgID)
			} else {
				appID := AuthorizedSubjectID(c, "application")
				if appID != nil {
					subject = fmt.Sprintf("application:%s", appID)
				} else {
					userID := AuthorizedSubjectID(c, "user")
					if userID != nil {
						subject = fmt.Sprintf("user|%s", userID)
					}
				}
			}

			common.TrackAPICall(c, subject)
		}()
		c.Next()
	}
}

func requireTLSConfiguration() {
	certificate := os.Getenv("TLS_CERTIFICATE")
	certificatePath := os.Getenv("TLS_CERTIFICATE_PATH")

	privateKeyPath := os.Getenv("TLS_PRIVATE_KEY_PATH")
	privateKey := os.Getenv("TLS_PRIVATE_KEY")

	if certificatePath != "" && privateKeyPath != "" {
		if certificate != "" || privateKey != "" {
			log.Printf("ambiguous TLS configuration provided")
			os.Exit(1)
		}

		CertificatePath = certificatePath
		PrivateKeyPath = privateKeyPath
		ServeTLS = true
	} else if certificate != "" && privateKey != "" {
		if certificatePath != "" || privateKeyPath != "" {
			log.Printf("ambiguous TLS configuration provided")
			os.Exit(1)
		}

		uuidStr, _ := uuid.NewV4()

		certPath := append([]string{os.TempDir()}, fmt.Sprintf(".%s.server.crt", uuidStr))
		keyPath := append([]string{os.TempDir()}, fmt.Sprintf(".%s.server.key", uuidStr))

		CertificatePath = filepath.FromSlash(strings.ReplaceAll(filepath.Join(certPath...), string(os.PathSeparator), "/"))
		err := os.WriteFile(CertificatePath, []byte(strings.ReplaceAll(certificate, "\\n", "\n")), 0600)
		if err != nil {
			log.Printf("failed to write TLS certificate to temporary file; %s", err.Error())
			os.Exit(1)
		}

		PrivateKeyPath = filepath.FromSlash(strings.ReplaceAll(filepath.Join(keyPath...), string(os.PathSeparator), "/"))
		err = os.WriteFile(PrivateKeyPath, []byte(strings.ReplaceAll(privateKey, "\\n", "\n")), 0600)
		if err != nil {
			log.Printf("failed to write TLS private key to temporary file; %s", err.Error())
			os.Exit(1)
		}

		ServeTLS = true
	} else if os.Getenv("REQUIRE_TLS") == "true" {
		privKeyPath, certPath, err := selfsignedcert.GenerateToDisk([]string{})
		if err != nil {
			common.Log.Panicf("failed to generate self-signed certificate; %s", err.Error())
		}
		PrivateKeyPath = *privKeyPath
		CertificatePath = *certPath
		ServeTLS = true
	}
}
