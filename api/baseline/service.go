package baseline

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/provideplatform/provide-go/api"
	"github.com/provideplatform/provide-go/common"
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
	if os.Getenv("BASELINE_API_PATH") != "" {
		path = os.Getenv("BASELINE_API_PATH")
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

// ListSubjectAccounts creates a BPI subject account using the given organization and params
func ListSubjectAccounts(token, organizationID string, params map[string]interface{}) ([]*SubjectAccount, error) {
	uri := fmt.Sprintf("subjects/%s/accounts", organizationID)
	status, resp, err := InitBaselineService(token).Post(uri, params)
	if err != nil {
		return nil, fmt.Errorf("failed to list BPI subject accounts; status: %v; %s", status, err.Error())
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to list BPI subject accounts; status: %v", status)
	}

	subjectAccounts := make([]*SubjectAccount, 0)
	for _, item := range resp.([]interface{}) {
		subjectAccount := &SubjectAccount{}
		subjectAccountRaw, _ := json.Marshal(item)
		json.Unmarshal(subjectAccountRaw, &subjectAccount)
		subjectAccounts = append(subjectAccounts, subjectAccount)
	}

	return subjectAccounts, nil
}

// CreateSubjectAccount creates a BPI subject account using the given organization and params
func CreateSubjectAccount(token, organizationID string, params map[string]interface{}) (*SubjectAccount, error) {
	uri := fmt.Sprintf("subjects/%s/accounts", organizationID)
	status, resp, err := InitBaselineService(token).Post(uri, params)
	if err != nil {
		return nil, fmt.Errorf("failed to create BPI subject account; status: %v; %s", status, err.Error())
	}

	if status != 201 {
		return nil, fmt.Errorf("failed to create BPI subject account; status: %v", status)
	}

	subjectAccount := &SubjectAccount{}
	subjectAccountRaw, _ := json.Marshal(resp)
	err = json.Unmarshal(subjectAccountRaw, &subjectAccount)

	return subjectAccount, nil
}

// UpdateSubjectAccount updates a BPI subject account
func UpdateSubjectAccount(token, organizationID, subjectAccountID string, params map[string]interface{}) error {
	uri := fmt.Sprintf("subjects/%s/accounts/%s", organizationID, subjectAccountID)
	status, _, err := InitBaselineService(token).Put(uri, params)
	if err != nil {
		return fmt.Errorf("failed to create BPI subject account; status: %v; %s", status, err.Error())
	}

	if status != 201 {
		return fmt.Errorf("failed to create BPI subject account; status: %v", status)
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

// ListWorkflows retrieves a paginated list of baseline workflows scoped to the given API token
func ListWorkflows(token string, params map[string]interface{}) ([]*Workflow, error) {
	status, resp, err := InitBaselineService(token).Get("workflows", params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to list baseline workflows; status: %v", status)
	}

	workflows := make([]*Workflow, 0)
	for _, item := range resp.([]interface{}) {
		workflow := &Workflow{}
		workflowraw, _ := json.Marshal(item)
		json.Unmarshal(workflowraw, &workflow)
		workflows = append(workflows, workflow)
	}

	return workflows, nil
}

// CreateWorkflow initializes a new workflow on the local baseline stack
func CreateWorkflow(token string, params map[string]interface{}) (*Workflow, error) {
	status, resp, err := InitBaselineService(token).Post("workflows", params)
	if err != nil {
		return nil, fmt.Errorf("failed to create workflow; status: %v; %s", status, err.Error())
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to create workflow; status: %v", status)
	}

	workflow := &Workflow{}
	workflowraw, _ := json.Marshal(resp)
	err = json.Unmarshal(workflowraw, &workflow)

	return workflow, nil
}

// ListWorksteps retrieves a paginated list of baseline worksteps scoped to the given API token
func ListWorksteps(token, workflowID string, params map[string]interface{}) ([]*Workstep, error) {
	uri := fmt.Sprintf("workflows/%s/worksteps", workflowID)
	status, resp, err := InitBaselineService(token).Get(uri, params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to list baseline worksteps; status: %v", status)
	}

	worksteps := make([]*Workstep, 0)
	for _, item := range resp.([]interface{}) {
		workstep := &Workstep{}
		workstepraw, _ := json.Marshal(item)
		json.Unmarshal(workstepraw, &workstep)
		worksteps = append(worksteps, workstep)
	}

	return worksteps, nil
}

// CreateWorkstep initializes a new workstep on the local baseline stack
func CreateWorkstep(token, workflowID string, params map[string]interface{}) (*Workstep, error) {
	uri := fmt.Sprintf("workflows/%s/worksteps", workflowID)
	status, resp, err := InitBaselineService(token).Post(uri, params)
	if err != nil {
		return nil, fmt.Errorf("failed to create workstep; status: %v; %s", status, err.Error())
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to create workstep; status: %v", status)
	}

	workstep := &Workstep{}
	workstepraw, _ := json.Marshal(resp)
	err = json.Unmarshal(workstepraw, &workstep)

	return workstep, nil
}

// ExecuteWorkstep executes a specific workstep
func ExecuteWorkstep(token, workflowID, workstepID string, params map[string]interface{}) (interface{}, error) {
	uri := fmt.Sprintf("workflows/%s/worksteps/%s/execute", workflowID, workstepID)
	status, resp, err := InitBaselineService(token).Post(uri, params)
	if err != nil {
		return nil, fmt.Errorf("failed to execute workstep; status: %v; %s", status, err.Error())
	}

	if status != 202 {
		return nil, fmt.Errorf("failed to execute workstep; status: %v", status)
	}

	return resp, nil
}

// CreateObject is a generic way to baseline a business object
func CreateObject(token string, params map[string]interface{}) (interface{}, error) {
	status, resp, err := InitBaselineService(token).Post("objects", params)
	if err != nil {
		return nil, fmt.Errorf("failed to create baseline object; status: %v; %s", status, err.Error())
	}

	if status != 202 {
		return nil, fmt.Errorf("failed to create baseline object; status: %v", status)
	}

	return resp, nil
}

// UpdateObject updates a business object
func UpdateObject(token, id string, params map[string]interface{}) error {
	uri := fmt.Sprintf("objects/%s", id)
	status, _, err := InitBaselineService(token).Put(uri, params)
	if err != nil {
		return fmt.Errorf("failed to update baseline state; status: %v; %s", status, err.Error())
	}

	if status != 202 {
		return fmt.Errorf("failed to update baseline state; status: %v", status)
	}

	return nil
}

// SendProtocolMessage is a generic way to dispatch a protocol message
func SendProtocolMessage(token string, params map[string]interface{}) (interface{}, error) {
	status, resp, err := InitBaselineService(token).Post("protocol_messages", params)
	if err != nil {
		return nil, fmt.Errorf("failed to dispatch baseline protocol message; status: %v; %s", status, err.Error())
	}

	if status != 202 {
		return nil, fmt.Errorf("failed to dispatch baseline protocol message; status: %v", status)
	}

	return resp, nil
}

// Status returns the status of the service
func Status() error {
	host := defaultBaselineHost
	if os.Getenv("BASELINE_API_HOST") != "" {
		host = os.Getenv("BASELINE_API_HOST")
	}

	scheme := defaultBaselineScheme
	if os.Getenv("BASELINE_API_SCHEME") != "" {
		scheme = os.Getenv("BASELINE_API_SCHEME")
	}

	service := &Service{
		api.Client{
			Host:   host,
			Path:   "",
			Scheme: scheme,
		},
	}

	status, _, err := service.Get("status", map[string]interface{}{})
	if err != nil {
		return fmt.Errorf("failed to fetch status; %s", err.Error())
	}

	if status != 204 {
		return fmt.Errorf("status endpoint returned %d status code", status)
	}

	return nil
}
