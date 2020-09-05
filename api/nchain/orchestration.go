package nchain

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

// NetworkInterface represents a common network interface
type NetworkInterface struct {
	Host        *string
	IPv4        *string
	IPv6        *string
	PrivateIPv4 *string
	PrivateIPv6 *string
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
