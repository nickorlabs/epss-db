import os
import vulncheck_sdk

DEFAULT_HOST = "https://api.vulncheck.com"
DEFAULT_API = DEFAULT_HOST + "/v3"
TOKEN = os.environ.get("VULNCHECK_API_TOKEN") or open("/run/secrets/vulncheck_api_key").read().strip()

configuration = vulncheck_sdk.Configuration(host=DEFAULT_API)
configuration.api_key["Bearer"] = TOKEN

with vulncheck_sdk.ApiClient(configuration) as api_client:
    endpoints_client = vulncheck_sdk.EndpointsApi(api_client)
    api_response = endpoints_client.index_get()
    for index in api_response.data:
        print(index.name)
