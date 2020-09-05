package api

import (
	"time"

	uuid "github.com/kthomas/go.uuid"
)

// AutoIncrementingModel base class with int primary key
type AutoIncrementingModel struct {
	ID        uint      `gorm:"primary_key;column:id;default:nextval('accounts_id_seq'::regclass)" json:"id"`
	CreatedAt time.Time `sql:"not null;default:now()" json:"created_at,omitempty"`
	Errors    []*Error  `sql:"-" json:"-"`
}

// Model base class with uuid v4 primary key id
type Model struct {
	ID        uuid.UUID `sql:"primary_key;type:uuid;default:uuid_generate_v4()" json:"id"`
	CreatedAt time.Time `sql:"not null;default:now()" json:"created_at,omitempty"`
	Errors    []*Error  `sql:"-" json:"-"`
}

// IModel interface
// TODO-- this isn't actually used anywhere... decide if it should be or remove it.
type IModel interface {
	Create() bool
	Reload()
	Update() bool
	Validate() bool
}

// Error struct
type Error struct {
	Message *string `json:"message"`
	Status  *int    `json:"status,omitempty"`
}
