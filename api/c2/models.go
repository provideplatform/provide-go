package c2

import (
	"fmt"
	"net"
	"time"

	uuid "github.com/kthomas/go.uuid"

	"github.com/provideplatform/provide-go/api"
)

const nodeReachabilityTimeout = time.Millisecond * 2500

// ContainerParams is a structure of params common to AWS and Azure containers
type ContainerParams struct {
	Region             string
	ResourceGroupName  string
	Image              *string
	VirtualNetworkID   *string
	ContainerGroupName *string
	ContainerName      *string
	CPU                *int64
	Memory             *int64
	Entrypoint         []*string
	SecurityGroupIds   []string
	SubnetIds          []string
	Environment        map[string]interface{}
	Security           map[string]interface{}
}

// LoadBalancer instances represent a physical or virtual load balancer of a specific type
type LoadBalancer struct {
	api.Model

	NetworkID      uuid.UUID              `json:"network_id,omitempty"`
	ApplicationID  *uuid.UUID             `json:"application_id,omitempty"`
	OrganizationID *uuid.UUID             `json:"organization_id,omitempty"`
	Name           *string                `json:"name"`
	Description    *string                `json:"description"`
	Type           *string                `json:"type"`
	Host           *string                `json:"host"`
	IPv4           *string                `json:"ipv4"`
	IPv6           *string                `json:"ipv6"`
	Region         *string                `json:"region"`
	Status         *string                `json:"status"`
	Config         map[string]interface{} `json:"config"`
}

// DNSName returns the preferred DNS name for the load balancer
func (l *LoadBalancer) DNSName() *string {
	var dnsName *string
	if dns, dnsOk := l.Config["dns"].([]interface{}); dnsOk {
		for _, item := range dns {
			if name, nameOk := item.(string); nameOk {
				dnsName = &name
				break
			}
		}
	}
	if dnsName == nil {
		if l.Host != nil {
			dnsName = l.Host
		} else if l.IPv4 != nil {
			dnsName = l.IPv4
		} else if l.IPv6 != nil {
			dnsName = l.IPv6
		}
	}
	return dnsName
}

// ReachableOnPort returns true if the given load balancer port is reachable via TCP
func (l *LoadBalancer) ReachableOnPort(port uint) bool {
	if l.Host == nil {
		return false
	}
	addr := fmt.Sprintf("%s:%v", *l.Host, port)
	conn, err := net.DialTimeout("tcp", addr, nodeReachabilityTimeout)
	if err == nil {
		defer conn.Close()
		return true
	}
	return false
}

// NetworkInterface represents a common network interface
type NetworkInterface struct {
	Host        *string
	IPv4        *string
	IPv6        *string
	PrivateIPv4 *string
	PrivateIPv6 *string
}

// Node instances represent physical or virtual, cloud-agnostic infrastructure on a network
type Node struct {
	api.Model

	NetworkID      uuid.UUID              `json:"network_id"`
	UserID         *uuid.UUID             `json:"user_id"`
	ApplicationID  *uuid.UUID             `json:"application_id"`
	OrganizationID *uuid.UUID             `json:"organization_id"`
	Bootnode       bool                   `json:"-"`
	Host           *string                `json:"host"`
	IPv4           *string                `json:"ipv4"`
	IPv6           *string                `json:"ipv6"`
	PrivateIPv4    *string                `json:"private_ipv4"`
	PrivateIPv6    *string                `json:"private_ipv6"`
	Description    *string                `json:"description"`
	Role           *string                `json:"role"`
	Status         *string                `json:"status"`
	Config         map[string]interface{} `json:"config"`
	ResourceGroupName *uuid.UUID          `json:"resource_group_name"`
	ProviderDetails   map[string]interface{} `sql:"-" json:"provider_details,omitempty"`
}

// ReachableOnPort returns true if the given node port is reachable via TCP
func (n *Node) ReachableOnPort(port uint) bool {
	if n.Host == nil {
		return false
	}
	addr := fmt.Sprintf("%s:%v", *n.Host, port)
	conn, err := net.DialTimeout("tcp", addr, nodeReachabilityTimeout)
	if err == nil {
		defer conn.Close()
		return true
	}
	return false
}

// NodeLog represents an abstract API response containing syslog or similar messages
type NodeLog struct {
	Timestamp       *int64 `json:"timestamp"`
	IngestTimestamp *int64 `json:"ingest_timestamp"`
	Message         string `json:"message"`
}

// NodeLogsResponse represents an abstract API response containing NodeLogs
// and pointer tokens to the next set of events in the stream
type NodeLogsResponse struct {
	Logs      []*NodeLog `json:"logs"`
	PrevToken *string    `json:"prev_token"`
	NextToken *string    `json:"next_token"`
}

// ContainerCreateResult is a struct representing the response from container creation function.
type ContainerCreateResult struct {
	ContainerIds        []string
	ContainerInterfaces []*NetworkInterface
}

// TargetCredentials struct has all credentials to access AWS and Azure in one place
type TargetCredentials struct {
	AWSAccessKeyID     *string
	AWSSecretAccessKey *string

	AzureSubscriptionID *string
	AzureTenantID       *string
	AzureClientID       *string
	AzureClientSecret   *string
}

// IsValidAWSCredentials returns `true` if the `TargetCredentials` struct has both `AWSAccessKeyID` and `AWSSecretAccessKey`
func (t *TargetCredentials) IsValidAWSCredentials() bool {
	return t.AWSAccessKeyID != nil && t.AWSSecretAccessKey != nil
}

// IsValidAzureCredentials returns `true` if the `TargetCredentials` struct has `AzureSubscriptionID`, `AzureTenantID`, `AzureClientID` and `AzureClientSecret`
func (t *TargetCredentials) IsValidAzureCredentials() bool {
	return t.AzureSubscriptionID != nil && t.AzureTenantID != nil && t.AzureClientID != nil && t.AzureClientSecret != nil
}
