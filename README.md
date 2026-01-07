# Uptycs Cloud Onboarding Tool

A command-line tool for managing cloud integrations with Uptycs, supporting AWS, GCP, Azure and IBM cloud providers.

## Features

- Create, update, and delete cloud integrations
- Support for multiple cloud providers:
  - Amazon Web Services (AWS)
  - Google Cloud Platform (GCP)
  - Microsoft Azure
  - IBM Cloud ( Only Account CSPM Integration )
- Manage different integration types:
  - Cloud accounts
  - Organizations
  - Log integrations
  - Scanner configurations
  - Target configurations
- Juno BYOK (Bring Your Own Key) credential management

## Prerequisites

- Python 3.x
- Uptycs API credentials (customer ID, key, secret, domain)
- Appropriate cloud provider credentials and permissions

## Installation

1. Clone this repository
2. Install the required dependencies:
```bash
pip install requests
```

## Configuration

Create a JSON configuration file with your Uptycs API credentials:

```json
{
    "customerId": "your-customer-id",
    "key": "your-api-key",
    "secret": "your-api-secret",
    "domain": "your-domain",
    "domainSuffix": ".uptycs.io"
}
```

## Usage

### Cloud Integration Operations

The basic command structure for cloud operations is:

```bash
python onboard.py --config <config_file> --cloud <provider> --action <action> --type <type> [additional options]
```

### Juno BYOK Operations

For Juno BYOK credential management:

```bash
python onboard.py --config <config_file> --juno --action <action> --type byok [additional options]
```

### Required Arguments

#### For Cloud Operations
- `--config`: Path to Uptycs API configuration file
- `--cloud`: Cloud provider (aws, gcp, azure, ibm)
- `--action`: Action to perform (create, update, delete, purge, get)
- `--type`: Integration type (account, organization, logs, scanner, target, logs-pubsub)
- `--tenant-id`: Tenant/Account ID (for cloud operations)
- `--integration-prefix`: Integration prefix (for cloud operations)

#### For Juno BYOK Operations
- `--config`: Path to Uptycs API configuration file
- `--juno`: Flag to indicate Juno operations
- `--action`: Action to perform (create, update, delete, get)
- `--type`: Must be `byok` (only valid type for Juno operations)
- `--key`: AWS access key ID (required for create/update)
- `--secret`: AWS secret access key (required for create/update)
- `--region`: AWS region (optional, default: us-east-1)

### Cloud-Specific Arguments

#### AWS
- `--tenant-name`: Account name (required for account creation)
- `--role-arn`: IAM role ARN
- `--external-id`: External ID for IAM role
- `--integration-type`: Integration type (CLOUD_FORMATION_V2, SELF_MANAGED, etc.)


#### GCP
- `--host-project-number`: Host project number
- `--host-project-id`: Host project ID

#### Azure
- `--azure-tenant-id`: Azure tenant ID
- `--azure-subscription-id`: Azure subscription ID

#### IBM
- `--profile-id`: Trusted Profile ID
- `--object-group-id`: Asset Group Id

### Examples

1. Create an AWS account integration:
```bash
python onboard.py --config config.json \
    --cloud aws \
    --action create \
    --type account \
    --tenant-id "123456789012" \
    --tenant-name "Production" \
    --role-arn "arn:aws:iam::123456789012:role/UptycsRole" \
    --external-id "your-external-id" \
    --integration-type "CLOUD_FORMATION_V2" \
    --integration-prefix "prod"
```

2. Create a GCP project integration:
```bash
python onboard.py --config config.json \
    --cloud gcp \
    --action create \
    --type account \
    --tenant-id "project-id" \
    --host-project-number "123456789" \
    --integration-prefix "gcp-prod"
```

3. Delete an Azure integration:
```bash
python onboard.py --config config.json \
    --cloud azure \
    --action delete \
    --type account \
    --tenant-id "subscription-id"
```

4. Create Juno BYOK credentials:
```bash
python onboard.py --config config.json \
    --juno \
    --action create \
    --type byok \
    --key "AKIAIOSFODNN7EXAMPLE" \
    --secret "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" \
    --region "us-east-1"
```

5. Get Juno BYOK credentials:
```bash
python onboard.py --config config.json \
    --juno \
    --action get \
    --type byok
```

6. Update Juno BYOK credentials:
```bash
python onboard.py --config config.json \
    --juno \
    --action update \
    --type byok \
    --key "AKIAIOSFODNN7EXAMPLE" \
    --secret "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" \
    --region "us-west-2"
```

7. Delete Juno BYOK credentials:
```bash
python onboard.py --config config.json \
    --juno \
    --action delete \
    --type byok
```

## Error Handling

The tool includes comprehensive error handling and will provide clear error messages if:
- Required arguments are missing
- API configuration is invalid
- Cloud provider credentials are incorrect
- API requests fail
- Invalid flag combinations (e.g., using `--type byok` without `--juno`)

## Important Notes

### Juno BYOK
- The `--type byok` option is **only** supported with the `--juno` flag
- BYOK operations require AWS credentials (access key ID and secret access key)
- The default AWS region is `us-east-1` if not specified
- Use the `get` action to retrieve existing BYOK credentials
- `create` and `update` actions require both `--key` and `--secret` parameters

## Support

For issues, questions, or feature requests, please contact Uptycs support or your account representative.

## License

See the [LICENSE](LICENSE) file for details.
