package ident

import (
	"fmt"
	"os"

	"github.com/provideservices/provide-go/api"
	"github.com/provideservices/provide-go/common"
)

const defaultIdentHost = "ident.provide.services"
const defaultIdentPath = "api/v1"
const defaultIdentScheme = "https"

// Ident client
type Ident struct {
	api.Client
}

// InitIdent convenience method
func InitIdent(token *string) *Ident {
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

	return &Ident{
		api.Client{
			Host:   host,
			Path:   path,
			Scheme: scheme,
			Token:  token,
		},
	}
}

// Authenticate a user by email address and password, returning a newly-authorized API token
func Authenticate(email, passwd string) (int, interface{}, error) {
	prvd := InitIdent(nil)
	return prvd.Post("authenticate", map[string]interface{}{
		"email":    email,
		"password": passwd,
	})
}

// CreateApplication on behalf of the given API token
func CreateApplication(token string, params map[string]interface{}) (int, interface{}, error) {
	return InitIdent(common.StringOrNil(token)).Post("applications", params)
}

// UpdateApplication using the given API token, application id and params
func UpdateApplication(token, applicationID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("applications/%s", applicationID)
	return InitIdent(common.StringOrNil(token)).Put(uri, params)
}

// ListApplications retrieves a paginated list of applications scoped to the given API token
func ListApplications(token string, params map[string]interface{}) (int, interface{}, error) {
	return InitIdent(common.StringOrNil(token)).Get("applications", params)
}

// GetApplicationDetails retrives application details for the given API token and application id
func GetApplicationDetails(token, applicationID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("applications/%s", applicationID)
	return InitIdent(common.StringOrNil(token)).Get(uri, params)
}

// ListApplicationTokens retrieves a paginated list of application API tokens
func ListApplicationTokens(token, applicationID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("applications/%s/tokens", applicationID)
	return InitIdent(common.StringOrNil(token)).Get(uri, params)
}

// CreateApplicationToken creates a new API token for the given application ID.
func CreateApplicationToken(token, applicationID string, params map[string]interface{}) (int, interface{}, error) {
	params["application_id"] = applicationID
	return InitIdent(common.StringOrNil(token)).Post("tokens", params)
}

// CreateToken creates a new API token.
func CreateToken(token string, params map[string]interface{}) (int, interface{}, error) {
	return InitIdent(common.StringOrNil(token)).Post("tokens", params)
}

// ListTokens retrieves a paginated list of API tokens scoped to the given API token
func ListTokens(token string, params map[string]interface{}) (int, interface{}, error) {
	return InitIdent(common.StringOrNil(token)).Get("tokens", params)
}

// GetTokenDetails retrieves details for the given API token id
func GetTokenDetails(token, tokenID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("tokens/%s", tokenID)
	return InitIdent(common.StringOrNil(token)).Get(uri, params)
}

// DeleteToken removes a previously authorized API token, effectively deauthorizing future calls using the token
func DeleteToken(token, tokenID string) (int, interface{}, error) {
	uri := fmt.Sprintf("tokens/%s", tokenID)
	return InitIdent(common.StringOrNil(token)).Delete(uri)
}

// CreateOrganization creates a new organization
func CreateOrganization(token string, params map[string]interface{}) (int, interface{}, error) {
	return InitIdent(common.StringOrNil(token)).Post("organizations", params)
}

// CreateUser creates a new user for which API tokens and managed signing identities can be authorized
func CreateUser(token string, params map[string]interface{}) (int, interface{}, error) {
	return InitIdent(common.StringOrNil(token)).Post("users", params)
}

// ListUsers retrieves a paginated list of users scoped to the given API token
func ListUsers(token string, params map[string]interface{}) (int, interface{}, error) {
	return InitIdent(common.StringOrNil(token)).Get("users", params)
}

// GetUserDetails retrieves details for the given user id
func GetUserDetails(token, userID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("users/%s", userID)
	return InitIdent(common.StringOrNil(token)).Get(uri, params)
}

// UpdateUser updates an existing user
func UpdateUser(token, userID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("users/%s", userID)
	return InitIdent(common.StringOrNil(token)).Put(uri, params)
}

// ListUserKYCApplications retrieves a paginated list of KYC applications by user, scoped to the given API token
func ListUserKYCApplications(token, userID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("users/%s/kyc_applications", userID)
	return InitIdent(common.StringOrNil(token)).Get(uri, params)
}

// CreateKYCApplication creates a new KYC application
func CreateKYCApplication(token string, params map[string]interface{}) (int, interface{}, error) {
	return InitIdent(common.StringOrNil(token)).Post("kyc_applications", params)
}

// UpdateKYCApplication updates an existing KYC application
func UpdateKYCApplication(token, kycApplicationID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("kyc_applications/%s", kycApplicationID)
	return InitIdent(common.StringOrNil(token)).Put(uri, params)
}

// GetKYCApplicationDetails retrieves details for the given user id
func GetKYCApplicationDetails(token, kycApplicationID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("kyc_applications/%s", kycApplicationID)
	return InitIdent(common.StringOrNil(token)).Get(uri, params)
}

// ListKYCApplications retrieves a paginated list of KYC applications scoped to the given API token
func ListKYCApplications(token string, params map[string]interface{}) (int, interface{}, error) {
	return InitIdent(common.StringOrNil(token)).Get("kyc_applications", params)
}
