package ident

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/provideservices/provide-go/api"
	"github.com/provideservices/provide-go/common"
)

const defaultIdentHost = "ident.provide.services"
const defaultIdentPath = "api/v1"
const defaultIdentScheme = "https"

// Service for the ident api
type Service struct {
	api.Client
}

// InitIdentService convenience method to initialize an `ident.Service` instance
func InitIdentService(token *string) *Service {
	host := defaultIdentHost
	if os.Getenv("IDENT_API_HOST") != "" {
		host = os.Getenv("IDENT_API_HOST")
	}

	path := defaultIdentPath
	if os.Getenv("IDENT_API_PATH") != "" {
		host = os.Getenv("IDENT_API_PATH")
	}

	scheme := defaultIdentScheme
	if os.Getenv("IDENT_API_SCHEME") != "" {
		scheme = os.Getenv("IDENT_API_SCHEME")
	}

	return &Service{
		api.Client{
			Host:   host,
			Path:   path,
			Scheme: scheme,
			Token:  token,
		},
	}
}

// Authenticate a user by email address and password, returning a newly-authorized API token
func Authenticate(email, passwd string) (*AuthenticationResponse, error) {
	prvd := InitIdentService(nil)
	status, resp, err := prvd.Post("authenticate", map[string]interface{}{
		"email":    email,
		"password": passwd,
	})
	if err != nil {
		return nil, err
	}

	// FIXME...
	authresp := &AuthenticationResponse{}
	raw, _ := json.Marshal(resp)
	err = json.Unmarshal(raw, &authresp)

	if err != nil {
		return nil, fmt.Errorf("failed to authenticate user; status: %v; %s", status, err.Error())
	}

	return authresp, nil
}

// CreateApplication on behalf of the given API token
func CreateApplication(token string, params map[string]interface{}) (*Application, error) {
	status, resp, err := InitIdentService(common.StringOrNil(token)).Post("applications", params)
	if err != nil {
		return nil, err
	}

	// FIXME...
	app := &Application{}
	appraw, _ := json.Marshal(resp)
	err = json.Unmarshal(appraw, &app)

	if err != nil {
		return nil, fmt.Errorf("failed to create application; status: %v; %s", status, err.Error())
	}

	return app, nil
}

// UpdateApplication using the given API token, application id and params
func UpdateApplication(token, applicationID string, params map[string]interface{}) error {
	uri := fmt.Sprintf("applications/%s", applicationID)
	status, _, err := InitIdentService(common.StringOrNil(token)).Put(uri, params)
	if err != nil {
		return err
	}

	if status != 204 {
		return fmt.Errorf("failed to update application; status: %v", status)
	}

	return nil
}

// ListApplications retrieves a paginated list of applications scoped to the given API token
func ListApplications(token string, params map[string]interface{}) ([]*Application, error) {
	status, resp, err := InitIdentService(common.StringOrNil(token)).Get("applications", params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to list applications; status: %v", status)
	}

	apps := make([]*Application, 0)
	for _, item := range resp.([]interface{}) {
		app := &Application{}
		appraw, _ := json.Marshal(item)
		json.Unmarshal(appraw, &app)
		apps = append(apps, app)
	}

	return apps, nil
}

// GetApplicationDetails retrives application details for the given API token and application id
func GetApplicationDetails(token, applicationID string, params map[string]interface{}) (*Application, error) {
	uri := fmt.Sprintf("applications/%s", applicationID)
	status, resp, err := InitIdentService(common.StringOrNil(token)).Get(uri, params)
	if err != nil {
		return nil, err
	}

	// FIXME...
	app := &Application{}
	appraw, _ := json.Marshal(resp)
	err = json.Unmarshal(appraw, &app)

	if err != nil {
		return nil, fmt.Errorf("failed to fetch application details; status: %v; %s", status, err.Error())
	}

	return app, nil
}

// ListApplicationTokens retrieves a paginated list of application API tokens
func ListApplicationTokens(token, applicationID string, params map[string]interface{}) ([]*Token, error) {
	uri := fmt.Sprintf("applications/%s/tokens", applicationID)
	status, resp, err := InitIdentService(common.StringOrNil(token)).Get(uri, params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to list application tokens; status: %v", status)
	}

	tkns := make([]*Token, 0)
	for _, item := range resp.([]interface{}) {
		tkn := &Token{}
		tknraw, _ := json.Marshal(item)
		json.Unmarshal(tknraw, &tkn)
		tkns = append(tkns, tkn)
	}

	return tkns, nil
}

// CreateApplicationToken creates a new API token for the given application ID.
func CreateApplicationToken(token, applicationID string, params map[string]interface{}) (*Token, error) {
	params["application_id"] = applicationID
	status, resp, err := InitIdentService(common.StringOrNil(token)).Post("tokens", params)
	if err != nil {
		return nil, err
	}

	// FIXME...
	tkn := &Token{}
	tknraw, _ := json.Marshal(resp)
	err = json.Unmarshal(tknraw, &tkn)

	if err != nil {
		return nil, fmt.Errorf("failed to authorize application token; status: %v; %s", status, err.Error())
	}

	return tkn, nil
}

// CreateToken creates a new API token.
func CreateToken(token string, params map[string]interface{}) (*Token, error) {
	status, resp, err := InitIdentService(common.StringOrNil(token)).Post("tokens", params)
	if err != nil {
		return nil, err
	}

	// FIXME...
	tkn := &Token{}
	tknraw, _ := json.Marshal(resp)
	err = json.Unmarshal(tknraw, &tkn)

	if err != nil {
		return nil, fmt.Errorf("failed to authorize tokens; status: %v; %s", status, err.Error())
	}

	return tkn, nil
}

// ListTokens retrieves a paginated list of API tokens scoped to the given API token
func ListTokens(token string, params map[string]interface{}) ([]*Token, error) {
	status, resp, err := InitIdentService(common.StringOrNil(token)).Get("tokens", params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to list application tokens; status: %v", status)
	}

	tkns := make([]*Token, 0)
	for _, item := range resp.([]interface{}) {
		tkn := &Token{}
		tknraw, _ := json.Marshal(item)
		json.Unmarshal(tknraw, &tkn)
		tkns = append(tkns, tkn)
	}

	return tkns, nil
}

// GetTokenDetails retrieves details for the given API token id
func GetTokenDetails(token, tokenID string, params map[string]interface{}) (*Token, error) {
	uri := fmt.Sprintf("tokens/%s", tokenID)
	status, resp, err := InitIdentService(common.StringOrNil(token)).Get(uri, params)
	if err != nil {
		return nil, err
	}

	// FIXME...
	tkn := &Token{}
	tknraw, _ := json.Marshal(resp)
	err = json.Unmarshal(tknraw, &tkn)

	if err != nil {
		return nil, fmt.Errorf("failed to fetch token details; status: %v; %s", status, err.Error())
	}

	return tkn, nil
}

// DeleteToken removes a previously authorized API token, effectively deauthorizing future calls using the token
func DeleteToken(token, tokenID string) error {
	uri := fmt.Sprintf("tokens/%s", tokenID)
	status, _, err := InitIdentService(common.StringOrNil(token)).Delete(uri)
	if err != nil {
		return err
	}

	if status != 204 {
		return fmt.Errorf("failed to revoke token; status: %v", status)
	}

	return nil
}

// CreateOrganization creates a new organization
func CreateOrganization(token string, params map[string]interface{}) (*Organization, error) {
	status, resp, err := InitIdentService(common.StringOrNil(token)).Post("organizations", params)
	if err != nil {
		return nil, err
	}

	// FIXME...
	org := &Organization{}
	orgraw, _ := json.Marshal(resp)
	err = json.Unmarshal(orgraw, &org)

	if err != nil {
		return nil, fmt.Errorf("failed to create organization; status: %v; %s", status, err.Error())
	}

	return org, nil
}

// CreateUser creates a new user for which API tokens and managed signing identities can be authorized
func CreateUser(token string, params map[string]interface{}) (*User, error) {
	status, resp, err := InitIdentService(common.StringOrNil(token)).Post("users", params)
	if err != nil {
		return nil, err
	}

	// FIXME...
	usr := &User{}
	usrraw, _ := json.Marshal(resp)
	err = json.Unmarshal(usrraw, &usr)

	if err != nil {
		return nil, fmt.Errorf("failed to create user; status: %v; %s", status, err.Error())
	}

	return usr, nil
}

// ListUsers retrieves a paginated list of users scoped to the given API token
func ListUsers(token string, params map[string]interface{}) ([]*User, error) {
	status, resp, err := InitIdentService(common.StringOrNil(token)).Get("users", params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to list users; status: %v", status)
	}

	users := make([]*User, 0)
	for _, item := range resp.([]interface{}) {
		usr := &User{}
		usrraw, _ := json.Marshal(item)
		json.Unmarshal(usrraw, &usr)
		users = append(users, usr)
	}

	return users, nil
}

// GetUserDetails retrieves details for the given user id
func GetUserDetails(token, userID string, params map[string]interface{}) (*User, error) {
	uri := fmt.Sprintf("users/%s", userID)
	status, resp, err := InitIdentService(common.StringOrNil(token)).Get(uri, params)
	if err != nil {
		return nil, err
	}

	// FIXME...
	usr := &User{}
	usrraw, _ := json.Marshal(resp)
	err = json.Unmarshal(usrraw, &usr)

	if err != nil {
		return nil, fmt.Errorf("failed to fetch user details; status: %v; %s", status, err.Error())
	}

	return usr, nil
}

// UpdateUser updates an existing user
func UpdateUser(token, userID string, params map[string]interface{}) error {
	uri := fmt.Sprintf("users/%s", userID)
	status, _, err := InitIdentService(common.StringOrNil(token)).Put(uri, params)
	if err != nil {
		return err
	}

	if status != 204 {
		return fmt.Errorf("failed to update user; status: %v", status)
	}

	return nil
}

// ListUserKYCApplications retrieves a paginated list of KYC applications by user, scoped to the given API token
func ListUserKYCApplications(token, userID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("users/%s/kyc_applications", userID)
	return InitIdentService(common.StringOrNil(token)).Get(uri, params)
}

// CreateKYCApplication creates a new KYC application
func CreateKYCApplication(token string, params map[string]interface{}) (int, interface{}, error) {
	return InitIdentService(common.StringOrNil(token)).Post("kyc_applications", params)
}

// UpdateKYCApplication updates an existing KYC application
func UpdateKYCApplication(token, kycApplicationID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("kyc_applications/%s", kycApplicationID)
	return InitIdentService(common.StringOrNil(token)).Put(uri, params)
}

// GetKYCApplicationDetails retrieves details for the given user id
func GetKYCApplicationDetails(token, kycApplicationID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("kyc_applications/%s", kycApplicationID)
	return InitIdentService(common.StringOrNil(token)).Get(uri, params)
}

// ListKYCApplications retrieves a paginated list of KYC applications scoped to the given API token
func ListKYCApplications(token string, params map[string]interface{}) (int, interface{}, error) {
	return InitIdentService(common.StringOrNil(token)).Get("kyc_applications", params)
}