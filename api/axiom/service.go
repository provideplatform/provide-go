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

package baseline

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/provideplatform/provide-go/api"
	"github.com/provideplatform/provide-go/common"
)

const defaultBaselineHost = "baseline.provide.services"
const defaultBaselinePath = "api/v1"
const defaultBaselineScheme = "https"

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

// ListMappings lists mappings using the given params
func ListMappings(token string, params map[string]interface{}) ([]*Mapping, error) {
	status, resp, err := InitBaselineService(token).Get("mappings", params)
	if err != nil {
		return nil, fmt.Errorf("failed to list mappings; status: %v; %s", status, err.Error())
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to list mappings; status: %v", status)
	}

	mappings := make([]*Mapping, 0)
	for _, item := range resp.([]interface{}) {
		mapping := &Mapping{}
		mappingRaw, _ := json.Marshal(item)
		json.Unmarshal(mappingRaw, &mapping)
		mappings = append(mappings, mapping)
	}

	return mappings, nil
}

// CreateMapping creates a mapping using the given params
func CreateMapping(token string, params map[string]interface{}) (*Mapping, error) {
	status, resp, err := InitBaselineService(token).Post("mappings", params)
	if err != nil {
		return nil, fmt.Errorf("failed to create mapping; status: %v; %s", status, err.Error())
	}

	if status != 201 {
		return nil, fmt.Errorf("failed to create mapping; status: %v", status)
	}

	mapping := &Mapping{}
	mappingRaw, _ := json.Marshal(resp)
	err = json.Unmarshal(mappingRaw, &mapping)

	return mapping, nil
}

// UpdateMapping updates a mapping
func UpdateMapping(token, mappingID string, params map[string]interface{}) error {
	uri := fmt.Sprintf("mappings/%s", mappingID)
	status, _, err := InitBaselineService(token).Put(uri, params)
	if err != nil {
		return fmt.Errorf("failed to update mapping; status: %v; %s", status, err.Error())
	}

	if status != 204 {
		return fmt.Errorf("failed to update mapping; status: %v", status)
	}

	return nil
}

// DeleteMapping deletes a mapping
func DeleteMapping(token, mappingID string) error {
	uri := fmt.Sprintf("mappings/%s", mappingID)
	status, _, err := InitBaselineService(token).Delete(uri)
	if err != nil {
		return fmt.Errorf("failed to delete mapping; status: %v; %s", status, err.Error())
	}

	if status != 204 {
		return fmt.Errorf("failed to delete mapping; status: %v", status)
	}

	return nil
}

// ListSubjectAccounts lists BPI subject accounts using the given organization and params
func ListSubjectAccounts(token, organizationID string, params map[string]interface{}) ([]*SubjectAccount, error) {
	uri := fmt.Sprintf("subjects/%s/accounts", organizationID)
	status, resp, err := InitBaselineService(token).Get(uri, params)
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

// GetSubjectAccountDetails retrieves details for the given BPI subject account id
func GetSubjectAccountDetails(token, organizationID, subjectAccountID string, params map[string]interface{}) (*SubjectAccount, error) {
	uri := fmt.Sprintf("subjects/%s/accounts/%s", organizationID, subjectAccountID)
	status, resp, err := InitBaselineService(token).Get(uri, params)
	if err != nil {
		return nil, err
	}

	subjectAccount := &SubjectAccount{}
	subjectAccountRaw, _ := json.Marshal(resp)
	err = json.Unmarshal(subjectAccountRaw, &subjectAccount)

	if err != nil {
		return nil, fmt.Errorf("failed to fetch BPI subject account details; status: %v; %s", status, err.Error())
	}

	return subjectAccount, nil
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
		return fmt.Errorf("failed to update BPI subject account; status: %v; %s", status, err.Error())
	}

	if status != 204 {
		return fmt.Errorf("failed to update BPI subject account; status: %v", status)
	}

	return nil
}

// ListWorkgroups retrieves a paginated list of baseline workgroups scoped to the given API token
func ListWorkgroups(token string, params map[string]interface{}) ([]*Workgroup, error) {
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

// GetWorkgroupDetails retrieves details for the given workgroup id
func GetWorkgroupDetails(token, workgroupID string, params map[string]interface{}) (*Workgroup, error) {
	uri := fmt.Sprintf("workgroups/%s", workgroupID)
	status, resp, err := InitBaselineService(token).Get(uri, params)
	if err != nil {
		return nil, err
	}

	workgroup := &Workgroup{}
	workgroupRaw, _ := json.Marshal(resp)
	err = json.Unmarshal(workgroupRaw, &workgroup)

	if err != nil {
		return nil, fmt.Errorf("failed to fetch workgroup details; status: %v; %s", status, err.Error())
	}

	return workgroup, nil
}

// CreateWorkgroup initializes a new or previously-joined workgroup on the local baseline stack
func CreateWorkgroup(token string, params map[string]interface{}) (*Workgroup, error) {
	status, resp, err := InitBaselineService(token).Post("workgroups", params)
	if err != nil {
		return nil, fmt.Errorf("failed to create workgroup; status: %v; %s", status, err.Error())
	}

	if status != 201 && status != 204 {
		return nil, fmt.Errorf("failed to create workgroup; status: %v", status)
	}

	if resp != nil {
		workgroup := &Workgroup{}
		workgroupraw, _ := json.Marshal(resp)
		err = json.Unmarshal(workgroupraw, &workgroup)

		return workgroup, nil
	}

	return nil, nil
}

// UpdateWorkgroup updates a baseline workgroup
func UpdateWorkgroup(token, workgroupID string, params map[string]interface{}) error {
	uri := fmt.Sprintf("workgroups/%s", workgroupID)
	status, _, err := InitBaselineService(token).Put(uri, params)
	if err != nil {
		return fmt.Errorf("failed to update workgroup; status: %v; %s", status, err.Error())
	}

	if status != 204 {
		return fmt.Errorf("failed to update workgroup; status: %v", status)
	}

	return nil
}

// FetchWorkgroupAnalytics retrieves analytics data for the given workgroupID
func FetchWorkgroupAnalytics(token, workgroupID string, params map[string]interface{}) (*WorkgroupDashboardAPIResponse, error) {
	uri := fmt.Sprintf("workgroups/%s/analytics", workgroupID)
	status, _, err := InitBaselineService(token).Get(uri, params)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch workgroup analytics; status: %v; %s", status, err.Error())
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to fetch workgroup analytics; status: %v", status)
	}

	var analytics WorkgroupDashboardAPIResponse
	analyticsRaw, _ := json.Marshal(analytics)
	err = json.Unmarshal(analyticsRaw, &analytics)

	return &analytics, nil
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
		workflowRaw, _ := json.Marshal(item)
		json.Unmarshal(workflowRaw, &workflow)
		workflows = append(workflows, workflow)
	}

	return workflows, nil
}

// GetWorkflowDetails retrieves details for the given workflow id
func GetWorkflowDetails(token, workflowID string, params map[string]interface{}) (*Workflow, error) {
	uri := fmt.Sprintf("workflows/%s", workflowID)
	status, resp, err := InitBaselineService(token).Get(uri, params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to fetch workflow details; status: %v", status)
	}

	workflow := &Workflow{}
	workflowRaw, _ := json.Marshal(resp)
	json.Unmarshal(workflowRaw, &workflow)

	return workflow, nil
}

// CreateWorkflow initializes a new workflow on the local baseline stack
func CreateWorkflow(token string, params map[string]interface{}) (*Workflow, error) {
	status, resp, err := InitBaselineService(token).Post("workflows", params)
	if err != nil {
		return nil, fmt.Errorf("failed to create workflow; status: %v; %s", status, err.Error())
	}

	if status != 201 {
		return nil, fmt.Errorf("failed to create workflow; status: %v", status)
	}

	workflow := &Workflow{}
	workflowraw, _ := json.Marshal(resp)
	err = json.Unmarshal(workflowraw, &workflow)

	return workflow, nil
}

// UpdateWorkflow updates a baseline workflow
func UpdateWorkflow(token, workflowID string, params map[string]interface{}) error {
	uri := fmt.Sprintf("workflows/%s", workflowID)
	status, _, err := InitBaselineService(token).Put(uri, params)
	if err != nil {
		return fmt.Errorf("failed to update workflow; status: %v; %s", status, err.Error())
	}

	if status != 204 {
		return fmt.Errorf("failed to update workflow; status: %v", status)
	}

	return nil
}

// DeployWorkflow deploys a workflow to the specified layer(s), preventing future changes
func DeployWorkflow(token, workflowID string, params map[string]interface{}) (*Workflow, error) {
	uri := fmt.Sprintf("workflows/%s/deploy", workflowID)
	status, resp, err := InitBaselineService(token).Post(uri, params)
	if err != nil {
		return nil, fmt.Errorf("failed to deploy workflow; status: %v; %s", status, err.Error())
	}

	if status != 202 {
		return nil, fmt.Errorf("failed to deploy workflow; status: %v", status)
	}

	workflow := &Workflow{}
	workflowRaw, _ := json.Marshal(resp)
	json.Unmarshal(workflowRaw, &workflow)

	return workflow, nil
}

// FetchWorkflowVersions returns all of the versions of a given workflow
func FetchWorkflowVersions(token, workflowID string, params map[string]interface{}) ([]*Workflow, error) {
	uri := fmt.Sprintf("workflows/%s/versions", workflowID)
	status, resp, err := InitBaselineService(token).Get(uri, params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to list baseline workflow versions; status: %v", status)
	}

	workflows := make([]*Workflow, 0)
	for _, item := range resp.([]interface{}) {
		workflow := &Workflow{}
		workflowRaw, _ := json.Marshal(item)
		json.Unmarshal(workflowRaw, &workflow)
		workflows = append(workflows, workflow)
	}

	return workflows, nil
}

// VersionWorkflow creates a new version of a previously deployed workflow
func VersionWorkflow(token, workflowID string, params map[string]interface{}) (*Workflow, error) {
	uri := fmt.Sprintf("workflows/%s/versions", workflowID)
	status, resp, err := InitBaselineService(token).Post(uri, params)
	if err != nil {
		return nil, err
	}

	if status != 201 {
		return nil, fmt.Errorf("failed to create workflow version; status: %v", status)
	}

	workflow := &Workflow{}
	workflowRaw, _ := json.Marshal(resp)
	json.Unmarshal(workflowRaw, &workflow)

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

// GetWorkstepDetails retrieves the details of a workstep
func GetWorkstepDetails(token, workflowID, workstepID string, params map[string]interface{}) (*Workstep, error) {
	uri := fmt.Sprintf("workflows/%s/worksteps/%s", workflowID, workstepID)
	status, resp, err := InitBaselineService(token).Get(uri, params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to get workstep details; status: %v", status)
	}

	workstep := &Workstep{}
	workstepraw, _ := json.Marshal(resp)
	json.Unmarshal(workstepraw, &workstep)

	return workstep, nil
}

// CreateWorkstep initializes a new workstep on the local baseline stack
func CreateWorkstep(token, workflowID string, params map[string]interface{}) (*Workstep, error) {
	uri := fmt.Sprintf("workflows/%s/worksteps", workflowID)
	status, resp, err := InitBaselineService(token).Post(uri, params)
	if err != nil {
		return nil, fmt.Errorf("failed to create workstep; status: %v; %s", status, err.Error())
	}

	if status != 201 {
		return nil, fmt.Errorf("failed to create workstep; status: %v", status)
	}

	workstep := &Workstep{}
	workstepraw, _ := json.Marshal(resp)
	err = json.Unmarshal(workstepraw, &workstep)

	return workstep, nil
}

// UpdateWorkstep updates a baseline workstep
func UpdateWorkstep(token, workflowID, workstepID string, params map[string]interface{}) error {
	uri := fmt.Sprintf("workflows/%s/worksteps/%s", workflowID, workstepID)
	status, _, err := InitBaselineService(token).Put(uri, params)
	if err != nil {
		return fmt.Errorf("failed to update workstep; status: %v; %s", status, err.Error())
	}

	if status != 204 {
		return fmt.Errorf("failed to update workstep; status: %v", status)
	}

	return nil
}

// ExecuteWorkstep executes a specific workstep
func ExecuteWorkstep(token, workflowID, workstepID string, params map[string]interface{}) (interface{}, error) {
	uri := fmt.Sprintf("workflows/%s/worksteps/%s/execute", workflowID, workstepID)
	status, resp, err := InitBaselineService(token).Post(uri, params)
	if err != nil {
		return nil, fmt.Errorf("failed to execute workstep; status: %v; %s", status, err.Error())
	}

	if status != 201 {
		return nil, fmt.Errorf("failed to execute workstep; status: %v", status)
	}

	return resp, nil
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

// ListSystems returns the systems for a workgroup
func ListSystems(token, workgroupID string, params map[string]interface{}) ([]*System, error) {
	uri := fmt.Sprintf("workgroups/%s/systems", workgroupID)
	status, resp, err := InitBaselineService(token).Get(uri, params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to list systems; status: %v", status)
	}

	systems := make([]*System, 0)
	for _, item := range resp.([]interface{}) {
		var system System
		systemRaw, _ := json.Marshal(item)
		json.Unmarshal(systemRaw, &system)
		systems = append(systems, &system)
	}

	return systems, nil
}

// GetSystemDetails returns the system details for a workgroup
func GetSystemDetails(token, workgroupID, systemID string, params map[string]interface{}) (*System, error) {
	uri := fmt.Sprintf("workgroups/%s/systems/%s", workgroupID, systemID)
	status, resp, err := InitBaselineService(token).Get(uri, params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to get system details; status: %v", status)
	}

	var system System
	systemRaw, _ := json.Marshal(resp)
	json.Unmarshal(systemRaw, &system)

	return &system, nil
}

// CreateSystem initializes a new system of record on the local baseline stack
func CreateSystem(token, workgroupID string, params map[string]interface{}) (*System, error) {
	uri := fmt.Sprintf("workgroups/%s/systems", workgroupID)
	status, resp, err := InitBaselineService(token).Post(uri, params)
	if err != nil {
		return nil, fmt.Errorf("failed to create system; status: %v; %s", status, err.Error())
	}

	if status != 201 {
		return nil, fmt.Errorf("failed to create system; status: %v", status)
	}

	var system System
	systemRaw, _ := json.Marshal(resp)
	json.Unmarshal(systemRaw, &system)

	return &system, nil
}

// UpdateSystem updates a baseline system of record
func UpdateSystem(token, workgroupID, systemID string, params map[string]interface{}) error {
	uri := fmt.Sprintf("workgroups/%s/systems/%s", workgroupID, systemID)
	status, _, err := InitBaselineService(token).Put(uri, params)
	if err != nil {
		return fmt.Errorf("failed to update system; status: %v; %s", status, err.Error())
	}

	if status != 204 {
		return fmt.Errorf("failed to update system; status: %v", status)
	}

	return nil
}

// DeleteSystem deletes a system
func DeleteSystem(token, workgroupID, systemID string) error {
	uri := fmt.Sprintf("workgroups/%s/systems/%s", workgroupID, systemID)
	status, _, err := InitBaselineService(token).Delete(uri)
	if err != nil {
		return fmt.Errorf("failed to delete system; status: %v; %s", status, err.Error())
	}

	if status != 204 {
		return fmt.Errorf("failed to delete system; status: %v", status)
	}

	return nil
}

// ListSchemas returns the schemas from a workgroup system of record
func ListSchemas(token, workgroupID string, params map[string]interface{}) ([]*Schema, error) {
	uri := fmt.Sprintf("workgroups/%s/schemas", workgroupID)
	status, resp, err := InitBaselineService(token).Get(uri, params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to list schemas; status: %v", status)
	}

	schemas := make([]*Schema, 0)
	for _, item := range resp.([]interface{}) {
		var schema Schema
		schemaRaw, _ := json.Marshal(item)
		json.Unmarshal(schemaRaw, &schema)
		schemas = append(schemas, &schema)
	}

	return schemas, nil
}

// GetSchemaDetails retrieves details for the given schema id
func GetSchemaDetails(token, workgroupID, schemaID string, params map[string]interface{}) (*Schema, error) {
	uri := fmt.Sprintf("workgroups/%s/schemas/%s", workgroupID, schemaID)
	status, resp, err := InitBaselineService(token).Get(uri, params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to get schema details; status: %v", status)
	}

	var schema Schema
	schemaRaw, _ := json.Marshal(resp)
	json.Unmarshal(schemaRaw, &schema)

	return &schema, nil
}

// SystemReachability returns whether a system of record is a valid tenant and if so, configures said tenant
func SystemReachability(token string, params map[string]interface{}) error {
	status, _, err := InitBaselineService(token).Post("systems/reachability", params)
	if err != nil {
		return err
	}

	if status != 204 {
		return fmt.Errorf("failed to check system reachability; status: %v", status)
	}

	return nil
}

// FetchWorkstepParticipants returns the participants for a given workstep
func FetchWorkstepParticipants(token, workflowID, workstepID string, params map[string]interface{}) ([]*Participant, error) {
	uri := fmt.Sprintf("workflows/%s/worksteps/%s/participants", workflowID, workstepID)
	status, resp, err := InitBaselineService(token).Get(uri, params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to fetch workstep participants; status: %v", status)
	}

	participants := make([]*Participant, 0)
	for _, item := range resp.([]interface{}) {
		var participant Participant
		participantRaw, _ := json.Marshal(item)
		json.Unmarshal(participantRaw, &participant)

		participants = append(participants, &participant)
	}

	return participants, nil
}

// CreateWorkstepParticipant adds a participant to a given workstep
func CreateWorkstepParticipant(token, workflowID, workstepID string, params map[string]interface{}) error {
	uri := fmt.Sprintf("workflows/%s/worksteps/%s/participants", workflowID, workstepID)
	status, _, err := InitBaselineService(token).Post(uri, params)
	if err != nil {
		return fmt.Errorf("failed to create workstep participant; status: %v; %s", status, err.Error())
	}

	if status != 204 {
		return fmt.Errorf("failed to create workstep participant; status: %v", status)
	}

	return nil
}

// DeleteWorkstepParticipant removes a participant from a given workstep
func DeleteWorkstepParticipant(token, workflowID, workstepID, address string) error {
	uri := fmt.Sprintf("workflows/%s/worksteps/%s/participants/%s", workflowID, workstepID, address)
	status, _, err := InitBaselineService(token).Delete(uri)
	if err != nil {
		return fmt.Errorf("failed to delete workstep participant; status: %v; %s", status, err.Error())
	}

	if status != 204 {
		return fmt.Errorf("failed to delete workstep participant; status: %v", status)
	}

	return nil
}
