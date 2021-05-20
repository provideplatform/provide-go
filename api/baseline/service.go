package baseline

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/provideservices/provide-go/api"
	"github.com/provideservices/provide-go/common"
)

const defaultBaselineHost = "localhost:8080"
const defaultBaselinePath = "api/v1"
const defaultBaselineScheme = "http"

// Service for the baseline api
type Service struct {
	api.Client
}

// InitBaselineService convenience method to initialize a `baseline.Service` instance
func InitBaselineService(token string) *Service {
	host := defaultBaselineHost
	if os.Getenv("BASELINE_API_HOST") != "" {
		host = os.Getenv("BASELINE_API_HOST")
	}

	path := defaultBaselinePath
	if os.Getenv("BASELIEN_API_PATH") != "" {
		host = os.Getenv("BASELIEN_API_PATH")
	}

	scheme := defaultBaselineScheme
	if os.Getenv("BASELINE_API_SCHEME") != "" {
		scheme = os.Getenv("BASELINE_API_SCHEME")
	}

	return &Service{
		api.Client{
			Host:   host,
			Path:   path,
			Scheme: scheme,
			Token:  common.StringOrNil(token),
		},
	}
}

// ConfigureStack updates the global configuration on the local baseline stack
func ConfigureStack(token string, params map[string]interface{}) error {
	status, _, err := InitBaselineService(token).Put("config", params)
	if err != nil {
		return fmt.Errorf("failed to configure baseline stack; status: %v; %s", status, err.Error())
	}

	if status != 204 {
		return fmt.Errorf("failed to configure baseline stack; status: %v", status)
	}

	return nil
}

// CreateWorkgroup initializes a new or previously-joined workgroup on the local baseline stack
func CreateWorkgroup(token string, params map[string]interface{}) (*Workgroup, error) {
	status, resp, err := InitBaselineService(token).Post("workgroups", params)
	if err != nil {
		return nil, fmt.Errorf("failed to create workgroup; status: %v; %s", status, err.Error())
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to create workgroup; status: %v", status)
	}

	workgroup := &Workgroup{}
	workgroupraw, _ := json.Marshal(resp)
	err = json.Unmarshal(workgroupraw, &workgroup)

	return workgroup, nil
}

// UpdateWorkgroup updates a previously-initialized workgroup on the local baseline stack
func UpdateWorkgroup(id, token string, params map[string]interface{}) error {
	uri := fmt.Sprintf("workgroups/%s", id)
	status, _, err := InitBaselineService(token).Post(uri, params)
	if err != nil {
		return fmt.Errorf("failed to update workgroup; status: %v; %s", status, err.Error())
	}

	if status != 204 {
		return fmt.Errorf("failed to update workgroup; status: %v", status)
	}

	return nil
}

// ListWorkgroups retrieves a paginated list of baseline workgroups scoped to the given API token
func ListWorkgroups(token, applicationID string, params map[string]interface{}) ([]*Workgroup, error) {
	status, resp, err := InitBaselineService(token).Get("workgroups", params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to list baseline workgroups; status: %v", status)
	}

	workgroups := make([]*Workgroup, 0)
	for _, item := range resp.([]interface{}) {
		workgroup := &Workgroup{}
		workgroupraw, _ := json.Marshal(item)
		json.Unmarshal(workgroupraw, &workgroup)
		workgroups = append(workgroups, workgroup)
	}

	return workgroups, nil
}

// CreateBusinessObject is a generic way to baseline a business object
func CreateBusinessObject(token string, params map[string]interface{}) (interface{}, error) {
	status, resp, err := InitBaselineService(token).Post("business_objects", params)
	if err != nil {
		return nil, fmt.Errorf("failed to create business object; status: %v; %s", status, err.Error())
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to create business object; status: %v", status)
	}

	return resp, nil
}

// UpdateBusinessObject updates a business object
func UpdateBusinessObject(token, id string, params map[string]interface{}) error {
	uri := fmt.Sprintf("business_objects/%s", id)
	status, _, err := InitBaselineService(token).Put(uri, params)
	if err != nil {
		return fmt.Errorf("failed to update business object; status: %v; %s", status, err.Error())
	}

	if status != 200 {
		return fmt.Errorf("failed to update business object; status: %v", status)
	}

	return nil
}
