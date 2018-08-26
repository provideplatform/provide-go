package provide

// Goldmine
type Goldmine struct {
	APIClient
}

func InitGoldmine(token string) *Goldmine {
	return &Goldmine{
		APIClient{
			Host:   "goldmine.provide.services",
			Path:   "api/v1",
			Scheme: "https",
			Token:  stringOrNil(token),
		},
	}
}
