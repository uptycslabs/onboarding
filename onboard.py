import argparse
import base64
import hmac
import hashlib
import json
import requests
import sys
import time
from typing import Dict, Any, Optional

class UptycsAPI:
    def __init__(self, api_config_file: str = None, api_config: str = None):
        try:
            if not api_config_file and not api_config:
                raise ValueError("Either api_config_file or api_config must be specified")
            config_data = json.load(open(api_config_file)) if api_config_file else json.loads(api_config)
            required_fields = ['customerId', 'key', 'secret', 'domain', 'domainSuffix']
            for field in required_fields:
                if field not in config_data:
                    raise ValueError(f"{field} is required in API configuration")
            self.customer_id = config_data['customerId']
            self.key = config_data['key']
            self.secret = config_data['secret']
            self.base_url = f"https://{config_data['domain']}{config_data['domainSuffix']}"
            self.session = requests.Session()
            self._update_jwt_token()
        except Exception as e:
            print(f"Error initializing UptycsAPI: {e}")

    def _update_jwt_token(self):
        try:
            token = self._generate_jwt_token()
            self.session.headers.update({'Authorization': f'Bearer {token}'})
        except Exception as e:
            print(f"Error updating JWT token: {e}")

    def _generate_jwt_token(self) -> str:
        try:
            now = int(time.time())
            payload = {
                'iss': self.key,
                'iat': now,
                'exp': now + 300
            }
            header_b64 = self._encode_base64({'alg': 'HS256', 'typ': 'JWT'})
            payload_b64 = self._encode_base64(payload)
            signing_input = f"{header_b64}.{payload_b64}".encode()
            signature = self._sign_hmac(signing_input)
            return f"{header_b64}.{payload_b64}.{signature}"
        except Exception as e:
            print(f"Error generating JWT token: {e}")
            raise

    def _encode_base64(self, data: dict) -> str:
        try:
            return base64.urlsafe_b64encode(json.dumps(data, separators=(',', ':')).encode()).rstrip(b'=').decode()
        except Exception as e:
            print(f"Error encoding base64: {e}")
            raise

    def _sign_hmac(self, signing_input: bytes) -> str:
        try:
            signature = hmac.new(self.secret.encode(), signing_input, hashlib.sha256).digest()
            return base64.urlsafe_b64encode(signature).rstrip(b'=').decode()
        except Exception as e:
            print(f"Error signing HMAC: {e}")
            raise

    def _build_url(self, endpoint: str) -> str:
        try:
            prefix = "v2" if "agentless" in endpoint else ""
            if prefix:
                return f"{self.base_url}/public/api/{prefix}/customers/{self.customer_id}/{endpoint}"
            return f"{self.base_url}/public/api/customers/{self.customer_id}/{endpoint}"
        except Exception as e:
            print(f"Error building URL: {e}")
            raise

    def _make_request(self, method: str, endpoint: str, **kwargs) -> Any:
        try:
            url = self._build_url(endpoint)
            self._update_jwt_token()
            response = self.session.request(method, url, **kwargs)
            print(response.text)
            response.raise_for_status()
            if response.text.strip():
                try:
                    return response.json()
                except ValueError:
                    return response.text
            elif method == "DELETE":
                return {"status": "success", "code": response.status_code}
            else:
                return {}
        except requests.HTTPError as e:
            raise e
        except Exception as e:
            print(f"Error making API request: {e}")
    
    def get_tenant(self, tenant_id: str, connector_type: str, type: str) -> Optional[str]:
        try:
            endpoint = f'cloud/{connector_type}/organizations'
            response = self._make_request('GET', endpoint)
            if not response or not isinstance(response, dict) or 'items' not in response:
                print(f"No organizations found or unexpected response: {response}")
                return None

            for item in response['items']:
                if type == "organization":
                    for account in item.get('accounts', []):
                        if account.get('tenantId') == tenant_id:
                            return item.get('id')
                elif type == "account":
                    if any(acc.get('tenantId') == tenant_id for acc in item.get('accounts', [])):
                        return item.get('id')
            return None
        except Exception as e:
            print(f"Error getting organization ID: {e}")   

    def manage_type(self, action: str, type: str, connector_type: Optional[str], payload: Optional[dict] = None) -> Any:
        try:
            endpoint_map = {
                "account": "cloudAccounts",
                "organization": f"cloud/{connector_type}/organizations",
                "logs": "cloudTrailBuckets",
                "scanner": "agentless/integrations/scanner",
                "target": "agentless/integrations/target",
                "logs-pubsub": "cloudPubsub",
            }
            endpoint = endpoint_map.get(type, '')
            return self._make_request(action, endpoint, json=payload)
        except Exception as e:
            print(f"Error managing type: {e}") 

    def delete_type(self, tenant_id: str, type: str, connector_type: Optional[str] = None, name: Optional[str] = None) -> Optional[Dict[str, Any]]:
        try:
            if type == "account":
                accounts = self._make_request('GET', 'cloudAccounts')
                matching_account = next((acc for acc in accounts.get('items', []) if acc.get('tenantId') == tenant_id), None)
                if not matching_account:
                    raise ValueError(f"No account found with tenant ID: {tenant_id}")
                internal_id = matching_account.get('id')
                if not internal_id:
                    raise ValueError(f"No internal ID found for account with tenant ID: {tenant_id}")
                self._make_request('DELETE', f'cloudAccounts/{internal_id}')
            elif type == "organization" and connector_type:
                organization_id = self.get_tenant(tenant_id, connector_type, type)
                if not organization_id:
                    print(f"No organization found for tenant ID: {tenant_id}")
                    return None
                self._make_request('DELETE', f'cloud/{connector_type}/organizations/{organization_id}')
                return {"tenantId": tenant_id, "organizationId": organization_id}
            elif type == "logs":
                if not name:
                    self._make_request('DELETE', f'cloudTrailBuckets/{tenant_id}')
                else:
                    self._make_request('DELETE', f'cloudTrailBuckets/{tenant_id}/{name}')
            elif type == "logs-pubsub":
                self._make_request('DELETE', f'cloudPubsub/{tenant_id}')
            elif type == "scanner":
                self._make_request('DELETE', f'agentless/integrations/scanner/?connectorType={connector_type}&scannerTenantId={tenant_id}')
            elif type == "scannerpurge":
                self._make_request('DELETE', f'agentless/integrations/scanner/purge/?connectorType={connector_type}&scannerTenantId={tenant_id}')
            elif type == "target":
                self._make_request('DELETE', f'agentless/integrations/target/?connectorType={connector_type}&targetTenantId={tenant_id}')
            elif type == "targetpurge":
                self._make_request('DELETE', f'agentless/integrations/target/purge/?connectorType={connector_type}&targetTenantId={tenant_id}')
            else:
                print("Invalid type type or missing connector type.")
        except Exception as e:
            print(f"Error deleting type: {e}")

def validate_args(args, required_fields):
    missing_fields = [field for field in required_fields if not getattr(args, field, None)]
    if missing_fields:
        print(f"Error: Missing required arguments: {', '.join(missing_fields)}")
        sys.exit(1)

def parse_arguments():
    parser = argparse.ArgumentParser(description="Uptycs Cloud Onboarding Script v1.0.0")
    parser.add_argument("--config", required=True, help="Path to Uptycs API configuration file")
    parser.add_argument("--cloud", choices=["aws", "gcp", "azure"], required=True, help="Cloud provider")
    parser.add_argument("--action", choices=["create", "update", "delete", "purge"], required=True, help="Action to perform")
    parser.add_argument("--type", choices=["account", "organization", "logs", "scanner", "target", "logs-pubsub"], required=True, help="type type")
    
    # CSPM-specific arguments
    parser.add_argument("--tenant-id", help="Tenant/Account ID")
    parser.add_argument("--tenant-name", help="Tenant/Account Name (AWS only)")
    parser.add_argument("--role-arn", help="Role ARN (AWS only)")
    parser.add_argument("--external-id", help="External ID (AWS only)")
    parser.add_argument("--integration-prefix", help="Integration prefix (required for create/update)")
    parser.add_argument("--integration-type", help="Integration type (e.g., CLOUD_FORMATION_V2, SELF_MANAGED)")

    # GCP-specific arguments
    parser.add_argument("--host-project-number", help="Host project number (GCP only)")
    parser.add_argument("--host-project-id", help="Host project ID (GCP only)")

    # Azure-specific arguments
    parser.add_argument("--azure-tenant-id", help="Azure tenant ID")
    parser.add_argument("--azure-subscription-id", help="Azure subscription ID")

    # Logs arguments
    parser.add_argument("--bucket-name", help="Bucket name (logs only)")
    parser.add_argument("--bucket-region", help="Bucket region (logs only)")
    parser.add_argument("--bucket-prefix", help="Optional bucket prefix (logs only)")
    parser.add_argument("--topics", type=lambda s: [topic.strip() for topic in s.split(",")], help="pubsub topic names (comma-separated) (logs only)")
    parser.add_argument("--scope", choices=["account", "organization"], help="Scope (logs only)")

    # Scanner-specific arguments
    parser.add_argument("--scanner-id", help="Scanner ID")
    parser.add_argument("--regions", type=lambda s: [region.strip() for region in s.split(",")], help="Comma-separated list of regions")
    parser.add_argument("--disk-scanning", choices=["true", "false"], default="true", help="Enable disk scanning (AWS scanner only)")
    parser.add_argument("--lambda-scanning", choices=["true", "false"], default="true", help="Enable lambda scanning (AWS scanner only)")
    parser.add_argument("--bucket-data-scanning", choices=["true", "false"], default="false", help="Enable bucket data scanning (AWS scanner only)")
    
    # Target-specific arguments
    parser.add_argument("--uptycs-scanner", choices=["true", "false"], default="false", help="Enable Uptycs Managed Scanner (AWS scanner only)")

    return parser.parse_args()

def build_payload(type: str, connector_type: str, args, api: UptycsAPI) -> dict:
    if type in ["account", "organization", "scanner", "target"] and args.action not in ["delete", "update", "purge"]:
        integration_type = "SELF_MANAGED" if connector_type in ["gcp", "azure"] else args.integration_type
        if connector_type == "aws":
            valid_types = {
                "account": {"SELF_MANAGED", "CLOUD_FORMATION_V2"},
                "organization": {"SELF_MANAGED", "ORG_CLOUDFORMATION"},
                "scanner": {"SELF_MANAGED", "CLOUD_FORMATION"},
                "target": {"SELF_MANAGED", "CLOUD_FORMATION"},
            }.get(type, set())

            if args.integration_type not in valid_types:
                print(f"Error: Invalid --integration-type '{args.integration_type}' for AWS {type}. Must be one of {valid_types}.")
                sys.exit(1)
    else:
        integration_type = None

    integration_prefix = args.integration_prefix if type in ["account", "organization", "scanner"] else None
    payload = {}
    if type in ["account", "organization", "scanner"]:
        payload["integrationType"] = integration_type
        if type in ["account", "scanner"]:
            payload["integrationPrefix"] = integration_prefix
            payload["connectorType"] = connector_type
        elif type == "organization":
            if connector_type == "aws":
                payload["deploymentType"] = "uptycs"
                payload["integrationName"] = integration_prefix
            elif connector_type == "gcp":
                payload["hostProjectId"] = args.host_project_id
                payload["hostProjectNumber"] = args.host_project_number
                payload["integrationPrefix"] = integration_prefix
            elif connector_type == "azure":
                payload["integrationPrefix"] = integration_prefix

    if type == "account" and args.action == "create":
        payload["tenantId"] = args.tenant_id
        if connector_type == "aws":
            payload.update({
                "tenantName": args.tenant_name,
                "cloudformationTemplate": "https://uptycs-terraform-dev.s3.amazonaws.com/uptycs-account-cspm-integration-166.json",
                "accessConfig": {
                    "role_arn": args.role_arn,
                    "external_id": args.external_id
                }
            })
        elif connector_type == "gcp":
            if not args.host_project_number:
                print("Error: --host-project-number is required for GCP account integration.")
                sys.exit(1)
            payload["hostProjectNumber"] = args.host_project_number
        elif connector_type == "azure":
            if not args.azure_tenant_id:
                print("Error: --azure-tenant-id is required for Azure account integration.")
                sys.exit(1)
            payload["azureTenantId"] = args.azure_tenant_id

    elif type == "organization" and args.action == "create":
        payload["organizationId"] = args.tenant_id
        if connector_type == "aws":
            payload["awsExternalId"] = args.external_id

    elif type == "logs":
        payload.update({
            "tenantId": args.tenant_id,
            "bucketName": args.bucket_name,
            "bucketRegion": args.bucket_region,
            "bucketPrefix": args.bucket_prefix if args.bucket_prefix else None,
        })
        if connector_type == "aws" and args.role_arn and args.external_id:
            payload["accessConfig"] = {
                "role_arn": args.role_arn,
                "external_id": args.external_id
            }
            if args.scope == "organization":
                organization_id = api.get_tenant(args.tenant_id, connector_type, args.scope)
                if not organization_id:
                    print(f"Error: No organization found for tenant ID {args.tenant_id}.")
                    sys.exit(1)
                payload.update({"organizationId": organization_id})
    
    elif type == "logs-pubsub":
        if args.action == "create":
            payload.update({
                "tenantId": args.tenant_id,
                "subscriptionIds": args.topics,
                "jobType": "gcp_cloudlog_monitoring",
            })

    elif type == "scanner":
        payload.update({
            "tenantId": args.tenant_id,
            "regions": args.regions,
        })
        if connector_type == "aws":
            payload.update({
                "diskScanningEnabled": args.disk_scanning,
                "serverlessScanningEnabled": args.lambda_scanning,
                "bucketDataScanningEnabled": args.bucket_data_scanning,
            })

    elif type == "target":
        payload.update({
            "targetTenantId": args.tenant_id,
            "connectorType": connector_type,
        })
        if args.scanner_id == "uptycs":
            payload["uptycsScanner"] = True
        else:
            payload["scannerTenantId"] = args.scanner_id

    else:
        print(f"Error: Unsupported type {type}.")
        sys.exit(1)
    payload = {k: v for k, v in payload.items() if v is not None}
    return payload

def main():
    args = parse_arguments()
    try:
        api = UptycsAPI(args.config)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
    required_fields = ["tenant_id"]
    if args.type == "account":
        if args.action == "create":
            required_fields += ["integration_prefix"]
            if args.cloud == "aws":
                required_fields += ["tenant_name", "role_arn", "external_id", "integration_type"]
            elif args.cloud == "gcp":
                required_fields += ["host_project_number"]
            elif args.cloud == "azure":
                required_fields += ["azure_tenant_id"]

    elif args.type == "organization":
        if args.action == "create":
            required_fields += ["integration_prefix"]
            if args.cloud == "aws":
                required_fields += ["external_id", "integration_type"]
            if args.cloud == "gcp":
                required_fields += ["host_project_number", "host_project_id"]

    elif args.type == "logs":
        if args.action == "create":
            required_fields += ["bucket_name", "bucket_region"]
        elif args.action == "delete":
            required_fields += ["bucket_name"]
            name = args.bucket_name

    elif args.type == "logs-pubsub":
        if args.action == "create":
            required_fields += ["topics"]

    elif args.type == "scanner":
        required_fields += ["regions"]
        if args.action == "create":
            required_fields += ["integration_prefix"]
            if args.cloud == "aws":
                required_fields += ["disk_scanning", "lambda_scanning", "bucket_data_scanning", "integration_type"]
        elif args.action == "update":
            if args.cloud == "aws":
                required_fields += ["disk_scanning", "lambda_scanning", "bucket_data_scanning"]

    elif args.type == "target":
        if args.action == "create":
            required_fields += ["scanner_id", "cloud"]
            if args.cloud == "aws":
                if args.scanner_id == "uptycs":
                    required_fields += ["integration_type"]

    else:
        print(f"Error: Unsupported type {args.type}.")
        sys.exit(1)
    validate_args(args, required_fields)
    if args.action not in ["delete", "purge"]:
        payload = build_payload(args.type, args.cloud, args, api)
    if args.action == "create":
        api.manage_type("POST", args.type, args.cloud, payload)
    elif args.action == "update":
        api.manage_type("PUT", args.type, args.cloud, payload)
    elif args.action == "delete":
        api.delete_type(args.tenant_id, args.type, args.cloud, args.bucket_name)
    elif args.action == "purge":
        api.delete_type(args.tenant_id, f"{args.type}purge", args.cloud)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)
