# \CiIssuesApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**CiIssuesGetInstance**](CiIssuesApi.md#CiIssuesGetInstance) | **Get** /v1/ciIssues/{id} | 



## CiIssuesGetInstance

> CiIssueResponse CiIssuesGetInstance(ctx, id).FieldsCiIssues(fieldsCiIssues).Execute()



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
    fieldsCiIssues := []string{"FieldsCiIssues_example"} // []string | the fields to include for returned resources of type ciIssues (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.CiIssuesApi.CiIssuesGetInstance(context.Background(), id).FieldsCiIssues(fieldsCiIssues).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `CiIssuesApi.CiIssuesGetInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `CiIssuesGetInstance`: CiIssueResponse
    fmt.Fprintf(os.Stdout, "Response from `CiIssuesApi.CiIssuesGetInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiCiIssuesGetInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsCiIssues** | **[]string** | the fields to include for returned resources of type ciIssues | 

### Return type

[**CiIssueResponse**](CiIssueResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

