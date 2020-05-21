package provide

// ContainerParams is a structure of params common to AWS and Azure containers
type ContainerParams struct {
	region            string
	resourceGroupName string
	image             *string
	virtualNetworkID  *string
	cpu               *int64
	memory            *int64
	entrypoint        []*string
	securityGroupIds  []string
	subnetIds         []string
	environment       map[string]interface{}
	security          map[string]interface{}
}

// TargetCredentials struct has all credentials to access AWS and Azure in one place
type TargetCredentials struct {
        AWSAccessKeyID  *string
        AWSSecretAccessKey *string
        AzureSubscriptionID *string
        AzureTenantID *string
        AzureClientID *string
        AzureClientSecret *string
}

func (t *TargetCredentials) IsValidAWSCredentials() bool {
        return t.AWSAccessKeyID != nil && t.AWSSecretAccessKey != nil
}
