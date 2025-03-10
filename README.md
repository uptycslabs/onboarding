# Uptycs Cloud Onboarding Tool

A command-line tool for managing cloud integrations with Uptycs, supporting AWS, GCP, and Azure cloud providers.

## Features

- Create, update, and delete cloud integrations
- Support for multiple cloud providers:
  - Amazon Web Services (AWS)
  - Google Cloud Platform (GCP)
  - Microsoft Azure
- Manage different integration types:
  - Cloud accounts
  - Organizations
  - Log integrations
  - Scanner configurations
  - Target configurations

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

The basic command structure is:

```bash
python onboard.py --config <config_file> --cloud <provider> --action <action> --type <type> [additional options]
```

### Required Arguments

- `--config`: Path to Uptycs API configuration file
- `--cloud`: Cloud provider (aws, gcp, azure)
- `--action`: Action to perform (create, update, delete, purge)
- `--type`: Integration type (account, organization, logs, scanner, target, logs-pubsub)
- `--tenant-id`: Tenant/Account ID

### Cloud-Specific Arguments

#### AWS
- `--tenant-name`: Account name (required for account creation)
- `--role-arn`: IAM role ARN
- `--external-id`: External ID for IAM role
- `--integration-type`: Integration type (CLOUD_FORMATION_V2, SELF_MANAGED, etc.)
- `--integration-prefix`: Integration prefix

#### GCP
- `--host-project-number`: Host project number
- `--host-project-id`: Host project ID
- `--integration-prefix`: Integration prefix

#### Azure
- `--azure-tenant-id`: Azure tenant ID
- `--azure-subscription-id`: Azure subscription ID
- `--integration-prefix`: Integration prefix

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

## Error Handling

The tool includes comprehensive error handling and will provide clear error messages if:
- Required arguments are missing
- API configuration is invalid
- Cloud provider credentials are incorrect
- API requests fail

## Support

For issues, questions, or feature requests, please contact Uptycs support or your account representative.

## License

See the [LICENSE](LICENSE) file for details.
