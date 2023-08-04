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

package common

import (
	"crypto/sha256"
	"encoding/hex"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	logger "github.com/kthomas/go-logger"
)

const defaultzApplicationClaimsKey = "prvd"
const defaultJWTNatsClaimsKey = "nats"
const defaultJWTAuthorizationAudience = "https://provide.technology/api/v1"
const defaultJWTAuthorizationIssuer = "https://ident.provide.technology"
const defaultJWTAuthorizationTTL = time.Hour * 24
const defaultNatsJWTAuthorizationAudience = "https://websocket.provide.technology"

var (
	// Log is the configured logger
	Log *logger.Logger
)

func init() {
	Log = logger.NewLogger("provide-go", getLogLevel(), getSyslogEndpoint())
}

func getLogLevel() string {
	lvl := os.Getenv("LOG_LEVEL")
	if lvl == "" {
		lvl = "debug"
	}
	return lvl
}

func getSyslogEndpoint() *string {
	var endpoint *string
	if os.Getenv("SYSLOG_ENDPOINT") != "" {
		endpoint = StringOrNil(os.Getenv("SYSLOG_ENDPOINT"))
	}
	return endpoint
}

// ResolvePublicIP resolves the public IP of the caller
func ResolvePublicIP() (*string, error) {
	url := "https://api.ipify.org?format=text" // FIXME
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	ip, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	ipstr := string(ip)
	return &ipstr, nil
}

// StringOrNil returns a pointer to the string, or nil if the given string is empty
func StringOrNil(str string) *string {
	if str == "" {
		return nil
	}
	return &str
}

// SHA256 is a convenience method to return the sha256 hash of the given input
func SHA256(str string) string {
	digest := sha256.New()
	digest.Write([]byte(str))
	return hex.EncodeToString(digest.Sum(nil))
}
