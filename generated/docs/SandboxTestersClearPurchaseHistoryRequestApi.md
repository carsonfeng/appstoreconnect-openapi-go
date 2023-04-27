# \SandboxTestersClearPurchaseHistoryRequestApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**SandboxTestersClearPurchaseHistoryRequestCreateInstance**](SandboxTestersClearPurchaseHistoryRequestApi.md#SandboxTestersClearPurchaseHistoryRequestCreateInstance) | **Post** /v2/sandboxTestersClearPurchaseHistoryRequest | 



## SandboxTestersClearPurchaseHistoryRequestCreateInstance

> SandboxTestersClearPurchaseHistoryRequestV2Response SandboxTestersClearPurchaseHistoryRequestCreateInstance(ctx).SandboxTestersClearPurchaseHistoryRequestV2CreateRequest(sandboxTestersClearPurchaseHistoryRequestV2CreateRequest).Execute()



### Example

```go
package main

import (
    "context"
    "fmt"
    "os"
    openapiclient "github.com/GIT_USER_ID/GIT_REPO_ID"
)

func main() {
    sandboxTestersClearPurchaseHistoryRequestV2CreateRequest := *openapiclient.NewSandboxTestersClearPurchaseHistoryRequestV2CreateRequest(*openapiclient.NewSandboxTestersClearPurchaseHistoryRequestV2CreateRequestData("Type_example", *openapiclient.NewSandboxTestersClearPurchaseHistoryRequestV2CreateRequestDataRelationships(*openapiclient.NewSandboxTestersClearPurchaseHistoryRequestV2CreateRequestDataRelationshipsSandboxTesters([]openapiclient.SandboxTestersClearPurchaseHistoryRequestV2CreateRequestDataRelationshipsSandboxTestersDataInner{*openapiclient.NewSandboxTestersClearPurchaseHistoryRequestV2CreateRequestDataRelationshipsSandboxTestersDataInner("Type_example", "Id_example")})))) // SandboxTestersClearPurchaseHistoryRequestV2CreateRequest | SandboxTestersClearPurchaseHistoryRequest representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.SandboxTestersClearPurchaseHistoryRequestApi.SandboxTestersClearPurchaseHistoryRequestCreateInstance(context.Background()).SandboxTestersClearPurchaseHistoryRequestV2CreateRequest(sandboxTestersClearPurchaseHistoryRequestV2CreateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `SandboxTestersClearPurchaseHistoryRequestApi.SandboxTestersClearPurchaseHistoryRequestCreateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `SandboxTestersClearPurchaseHistoryRequestCreateInstance`: SandboxTestersClearPurchaseHistoryRequestV2Response
    fmt.Fprintf(os.Stdout, "Response from `SandboxTestersClearPurchaseHistoryRequestApi.SandboxTestersClearPurchaseHistoryRequestCreateInstance`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiSandboxTestersClearPurchaseHistoryRequestCreateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **sandboxTestersClearPurchaseHistoryRequestV2CreateRequest** | [**SandboxTestersClearPurchaseHistoryRequestV2CreateRequest**](SandboxTestersClearPurchaseHistoryRequestV2CreateRequest.md) | SandboxTestersClearPurchaseHistoryRequest representation | 

### Return type

[**SandboxTestersClearPurchaseHistoryRequestV2Response**](SandboxTestersClearPurchaseHistoryRequestV2Response.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

