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
	"os"

	"github.com/gin-gonic/gin"

	selfsignedcert "github.com/kthomas/go-self-signed-cert"
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

	// PrivateKeyPath is the private key used by HTTPS listener
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
			appID := AuthorizedSubjectID(c, "application")
			if appID != nil {
				subject = fmt.Sprintf("application:%s", appID)
			} else {
				userID := AuthorizedSubjectID(c, "user")
				if userID != nil {
					subject = fmt.Sprintf("user|%s", userID)
				}
			}

			common.TrackAPICall(c, subject)
		}()
		c.Next()
	}
}

func requireTLSConfiguration() {
	certificatePath := os.Getenv("TLS_CERTIFICATE_PATH")
	privateKeyPath := os.Getenv("TLS_PRIVATE_KEY_PATH")
	if certificatePath != "" && privateKeyPath != "" {
		CertificatePath = certificatePath
		PrivateKeyPath = privateKeyPath
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
