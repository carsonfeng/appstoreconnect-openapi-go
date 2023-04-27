# \CiArtifactsApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**CiArtifactsGetInstance**](CiArtifactsApi.md#CiArtifactsGetInstance) | **Get** /v1/ciArtifacts/{id} | 



## CiArtifactsGetInstance

> CiArtifactResponse CiArtifactsGetInstance(ctx, id).FieldsCiArtifacts(fieldsCiArtifacts).Execute()



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
    fieldsCiArtifacts := []string{"FieldsCiArtifacts_example"} // []string | the fields to include for returned resources of type ciArtifacts (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.CiArtifactsApi.CiArtifactsGetInstance(context.Background(), id).FieldsCiArtifacts(fieldsCiArtifacts).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `CiArtifactsApi.CiArtifactsGetInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `CiArtifactsGetInstance`: CiArtifactResponse
    fmt.Fprintf(os.Stdout, "Response from `CiArtifactsApi.CiArtifactsGetInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiCiArtifactsGetInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsCiArtifacts** | **[]string** | the fields to include for returned resources of type ciArtifacts | 

### Return type

[**CiArtifactResponse**](CiArtifactResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

