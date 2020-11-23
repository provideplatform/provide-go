package c2

import (
	"fmt"
	"os"

	"github.com/provideservices/provide-go/api"
	"github.com/provideservices/provide-go/common"
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
func ListNodes(token, networkID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("networks/%s/nodes", networkID)
	return InitC2Service(token).Get(uri, params)
}

// CreateNode creates and deploys a new node for the given authorization scope
func CreateNode(token, networkID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("networks/%s/nodes", networkID)
	return InitC2Service(token).Post(uri, params)
}

// GetNodeDetails fetches details for the given node
func GetNodeDetails(token, nodeID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("nodes/%s", nodeID)
	return InitC2Service(token).Get(uri, params)
}

// GetNodeLogs fetches the logs for the given node
func GetNodeLogs(token, nodeID string, params map[string]interface{}) (int, interface{}, error) {
	uri := fmt.Sprintf("nodes/%s/logs", nodeID)
	return InitC2Service(token).Get(uri, params)
}

// DeleteNode undeploys and deletes the given node
func DeleteNode(token, nodeID string) (int, interface{}, error) {
	uri := fmt.Sprintf("nodes/%s", nodeID)
	return InitC2Service(token).Delete(uri)
}
