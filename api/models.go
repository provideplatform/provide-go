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

package api

import (
	"fmt"
	"strings"
	"time"

	"github.com/jinzhu/gorm"
	uuid "github.com/kthomas/go.uuid"
)

// AutoIncrementingModel base class with int primary key
type AutoIncrementingModel struct {
	ID        uint      `gorm:"primary_key;column:id;default:nextval('accounts_id_seq'::regclass)" json:"id"`
	CreatedAt time.Time `sql:"not null;default:now()" json:"created_at,omitempty"`
	Errors    []*Error  `sql:"-" json:"errors,omitempty"`
}

// Model base class with uuid v4 primary key
type Model struct {
	ID        uuid.UUID `sql:"primary_key;type:uuid;default:uuid_generate_v4()" json:"id"`
	CreatedAt time.Time `sql:"not null;default:now()" json:"created_at,omitempty"`
	Errors    []*Error  `sql:"-" json:"errors,omitempty"`
}

// ModelWithDID base class with string-based primary key for DID support
type ModelWithDID struct {
	ID        *string   `sql:"primary_key" json:"id"`
	CreatedAt time.Time `sql:"not null;default:now()" json:"created_at,omitempty"`
	Errors    []*Error  `sql:"-" json:"errors,omitempty"`
}

// CRUD interface
type CRUD interface {
	Create(tx *gorm.DB) bool
	Delete(tx *gorm.DB) bool
	Reload()
	Update(tx *gorm.DB) bool
	Validate() bool
}

// Error struct
type Error struct {
	Message *string `json:"message"`
	Status  *int    `json:"status,omitempty"`
}

// Manifest defines the contents of a Provide release
type Manifest struct {
	Name       string             `json:"name"`
	Version    string             `json:"version"`
	Repository string             `json:"repository"`
	Packages   []*ManifestPackage `json:"packages"`
}

// ManifestPackage defines a single Manifest package
type ManifestPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Source  string `json:"source"`
	Image   string `json:"docker_image"`
	Type    string `json:"type"`
}

// RequestResponseContext
type RequestResponseContext interface {
	Flush()
	Get(key string) (value interface{}, exists bool)
	GetRawData() ([]byte, error)
	Header(key, value string)
	Param(key string) string
	Query(key string) string
	Status() int
	Size() int
	Write([]byte) (int, error)
	WriteHeader(statusCode int)
	WriteHeaderNow()
	WriteString(string) (int, error)
}

func (m *Manifest) GetImageVersion(image string) (*string, error) {
	for _, pkg := range m.Packages {
		if pkg.Image == strings.ToLower(image) {
			return &pkg.Version, nil
		}
	}

	return nil, fmt.Errorf("failed to resolve image version for package: %s", image)
}
