# \ScmPullRequestsApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**ScmPullRequestsGetInstance**](ScmPullRequestsApi.md#ScmPullRequestsGetInstance) | **Get** /v1/scmPullRequests/{id} | 



## ScmPullRequestsGetInstance

> ScmPullRequestResponse ScmPullRequestsGetInstance(ctx, id).FieldsScmPullRequests(fieldsScmPullRequests).Include(include).Execute()



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
    fieldsScmPullRequests := []string{"FieldsScmPullRequests_example"} // []string | the fields to include for returned resources of type scmPullRequests (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.ScmPullRequestsApi.ScmPullRequestsGetInstance(context.Background(), id).FieldsScmPullRequests(fieldsScmPullRequests).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `ScmPullRequestsApi.ScmPullRequestsGetInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `ScmPullRequestsGetInstance`: ScmPullRequestResponse
    fmt.Fprintf(os.Stdout, "Response from `ScmPullRequestsApi.ScmPullRequestsGetInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiScmPullRequestsGetInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsScmPullRequests** | **[]string** | the fields to include for returned resources of type scmPullRequests | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**ScmPullRequestResponse**](ScmPullRequestResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

