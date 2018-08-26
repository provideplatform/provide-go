package provide

// Ident
type Ident struct {
	APIClient
}

func InitIdent(token *string) *Ident {
	return &Ident{
		APIClient{
			Host:   "ident.provide.services",
			Path:   "api/v1",
			Scheme: "https",
			Token:  token,
		},
	}
}

func Authenticate(email, passwd string) (int, interface{}, error) {
	prvd := InitIdent(nil)
	return prvd.post("authenticate", map[string]interface{}{
		"email":    email,
		"password": passwd,
	})
}
