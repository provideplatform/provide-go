package c2

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/provideplatform/provide-go/api"
	"github.com/provideplatform/provide-go/common"
)

const defaultC2Host = "c2.provide.services"
const defaultC2Path = "api/v1"
const defaultC2Scheme = "https"

// Service for the c2 api
type Service struct {
	api.Client
}

// InitC2Service convenience method to initialize an `c2.Service` instance
func InitC2Service(token string) *Service {
	host := defaultC2Host
	if os.Getenv("C2_API_HOST") != "" {
		host = os.Getenv("C2_API_HOST")
	}

	path := defaultC2Path
	if os.Getenv("C2_API_PATH") != "" {
		host = os.Getenv("C2_API_PATH")
	}

	scheme := defaultC2Scheme
	if os.Getenv("C2_API_SCHEME") != "" {
		scheme = os.Getenv("C2_API_SCHEME")
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

// ListNodes list nodes for the given authorization scope
func ListNodes(token string, params map[string]interface{}) ([]*Node, error) {
	uri := fmt.Sprintf("nodes")
	status, resp, err := InitC2Service(token).Get(uri, params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to list nodes; status: %v", status)
	}

	nodes := make([]*Node, 0)
	for _, item := range resp.([]interface{}) {
		node := &Node{}
		raw, _ := json.Marshal(item)
		json.Unmarshal(raw, &node)
		nodes = append(nodes, node)
	}

	return nodes, nil
}

// CreateNode creates and deploys a new node for the given authorization scope
func CreateNode(token string, params map[string]interface{}) (*Node, error) {
	uri := fmt.Sprintf("nodes")
	status, resp, err := InitC2Service(token).Post(uri, params)
	if err != nil {
		return nil, err
	}

	if status != 201 { // correct response is 201 Created
		return nil, fmt.Errorf("failed to create node; status: %v", status)
	}

	// FIXME...
	node := &Node{}
	raw, _ := json.Marshal(resp)
	err = json.Unmarshal(raw, &node)
	if err != nil {
		return nil, fmt.Errorf("failed to create node; status: %v; %s", status, err.Error())
	}

	return node, nil
}

// GetNodeDetails fetches details for the given node
func GetNodeDetails(token, nodeID string, params map[string]interface{}) (*Node, error) {
	uri := fmt.Sprintf("nodes/%s", nodeID)
	status, resp, err := InitC2Service(token).Get(uri, params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to fetch node details; status: %v", status)
	}

	// FIXME...
	node := &Node{}
	raw, _ := json.Marshal(resp)
	err = json.Unmarshal(raw, &node)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch node details; status: %v; %s", status, err.Error())
	}

	return node, nil
}

// GetNodeLogs fetches the logs for the given node
func GetNodeLogs(token, nodeID string, params map[string]interface{}) (*NodeLogsResponse, error) {
	uri := fmt.Sprintf("nodes/%s/logs", nodeID)
	status, resp, err := InitC2Service(token).Get(uri, params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to fetch node logs; status: %v", status)
	}

	// FIXME...
	logsResponse := &NodeLogsResponse{}
	raw, _ := json.Marshal(resp)
	err = json.Unmarshal(raw, &logsResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch node logs; status: %v; %s", status, err.Error())
	}

	return logsResponse, nil
}

// DeleteNode undeploys and deletes the given node
func DeleteNode(token, nodeID string) (*Node, error) {
	uri := fmt.Sprintf("nodes/%s", nodeID)
	status, resp, err := InitC2Service(token).Delete(uri)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to delete node; status: %v", status)
	}

	node := &Node{}
	raw, _ := json.Marshal(resp)
	err = json.Unmarshal(raw, &node)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch node after delete; status: %v; %s", status, err.Error())
	}

	return node, nil
}

// ListLoadBalancers list load balancers for the given authorization scope
func ListLoadBalancers(token string, params map[string]interface{}) ([]*LoadBalancer, error) {
	status, resp, err := InitC2Service(token).Get("load_balancers", params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to list load balancers; status: %v", status)
	}

	balancers := make([]*LoadBalancer, 0)
	for _, item := range resp.([]interface{}) {
		balancer := &LoadBalancer{}
		raw, _ := json.Marshal(item)
		json.Unmarshal(raw, &balancer)
		balancers = append(balancers, balancer)
	}

	return balancers, nil
}

// CreateLoadBalancer creates and deploys a new load balancer for the given authorization scope
func CreateLoadBalancer(token string, params map[string]interface{}) (*LoadBalancer, error) {
	status, resp, err := InitC2Service(token).Post("load_balancers", params)
	if err != nil {
		return nil, err
	}

	if status != 200 {
		return nil, fmt.Errorf("failed to create load balancer; status: %v", status)
	}

	// FIXME...
	balancer := &LoadBalancer{}
	raw, _ := json.Marshal(resp)
	err = json.Unmarshal(raw, &balancer)
	if err != nil {
		return nil, fmt.Errorf("failed to create load balancer; status: %v; %s", status, err.Error())
	}

	return balancer, nil
}

// DeleteLoadBalancer undeploys and deletes the given load balancer
func DeleteLoadBalancer(token, loadBalancerID string) error {
	uri := fmt.Sprintf("load_balancers/%s", loadBalancerID)
	status, _, err := InitC2Service(token).Delete(uri)
	if err != nil {
		return err
	}

	if status != 204 {
		return fmt.Errorf("failed to delete load balancer; status: %v", status)
	}

	return nil
}
