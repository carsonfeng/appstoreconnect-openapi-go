# \SandboxTestersApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**SandboxTestersGetCollection**](SandboxTestersApi.md#SandboxTestersGetCollection) | **Get** /v2/sandboxTesters | 
[**SandboxTestersUpdateInstance**](SandboxTestersApi.md#SandboxTestersUpdateInstance) | **Patch** /v2/sandboxTesters/{id} | 



## SandboxTestersGetCollection

> SandboxTestersV2Response SandboxTestersGetCollection(ctx).FieldsSandboxTesters(fieldsSandboxTesters).Limit(limit).Execute()



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
    fieldsSandboxTesters := []string{"FieldsSandboxTesters_example"} // []string | the fields to include for returned resources of type sandboxTesters (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.SandboxTestersApi.SandboxTestersGetCollection(context.Background()).FieldsSandboxTesters(fieldsSandboxTesters).Limit(limit).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `SandboxTestersApi.SandboxTestersGetCollection``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `SandboxTestersGetCollection`: SandboxTestersV2Response
    fmt.Fprintf(os.Stdout, "Response from `SandboxTestersApi.SandboxTestersGetCollection`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiSandboxTestersGetCollectionRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **fieldsSandboxTesters** | **[]string** | the fields to include for returned resources of type sandboxTesters | 
 **limit** | **int32** | maximum resources per page | 

### Return type

[**SandboxTestersV2Response**](SandboxTestersV2Response.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## SandboxTestersUpdateInstance

> SandboxTesterV2Response SandboxTestersUpdateInstance(ctx, id).SandboxTesterV2UpdateRequest(sandboxTesterV2UpdateRequest).Execute()



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
    id := "id_example" // string | the id of the requested resource
    sandboxTesterV2UpdateRequest := *openapiclient.NewSandboxTesterV2UpdateRequest(*openapiclient.NewSandboxTesterV2UpdateRequestData("Type_example", "Id_example")) // SandboxTesterV2UpdateRequest | SandboxTester representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.SandboxTestersApi.SandboxTestersUpdateInstance(context.Background(), id).SandboxTesterV2UpdateRequest(sandboxTesterV2UpdateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `SandboxTestersApi.SandboxTestersUpdateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `SandboxTestersUpdateInstance`: SandboxTesterV2Response
    fmt.Fprintf(os.Stdout, "Response from `SandboxTestersApi.SandboxTestersUpdateInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiSandboxTestersUpdateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **sandboxTesterV2UpdateRequest** | [**SandboxTesterV2UpdateRequest**](SandboxTesterV2UpdateRequest.md) | SandboxTester representation | 

### Return type

[**SandboxTesterV2Response**](SandboxTesterV2Response.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

