package provide

// ContainerParams is a structure of params common to AWS and Azure containers
type ContainerParams struct {
	Region            string
	ResourceGroupName string
	Image             *string
	VirtualNetworkID  *string
	Cpu               *int64
	Memory            *int64
	Entrypoint        []*string
	SecurityGroupIds  []string
	SubnetIds         []string
	Environment       map[string]interface{}
	Security          map[string]interface{}
}

// ContainerCreateResult is a struct representing the response from container creation function.
type ContainerCreateResult struct {
	containerIds []string
	err          error
}

// TargetCredentials struct has all credentials to access AWS and Azure in one place
type TargetCredentials struct {
	AWSAccessKeyID      *string
	AWSSecretAccessKey  *string
	AzureSubscriptionID *string
	AzureTenantID       *string
	AzureClientID       *string
	AzureClientSecret   *string
}

func (t *TargetCredentials) IsValidAWSCredentials() bool {
	return t.AWSAccessKeyID != nil && t.AWSSecretAccessKey != nil
}
