# \ScmGitReferencesApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**ScmGitReferencesGetInstance**](ScmGitReferencesApi.md#ScmGitReferencesGetInstance) | **Get** /v1/scmGitReferences/{id} | 



## ScmGitReferencesGetInstance

> ScmGitReferenceResponse ScmGitReferencesGetInstance(ctx, id).FieldsScmGitReferences(fieldsScmGitReferences).Include(include).Execute()



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
    fieldsScmGitReferences := []string{"FieldsScmGitReferences_example"} // []string | the fields to include for returned resources of type scmGitReferences (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.ScmGitReferencesApi.ScmGitReferencesGetInstance(context.Background(), id).FieldsScmGitReferences(fieldsScmGitReferences).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `ScmGitReferencesApi.ScmGitReferencesGetInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `ScmGitReferencesGetInstance`: ScmGitReferenceResponse
    fmt.Fprintf(os.Stdout, "Response from `ScmGitReferencesApi.ScmGitReferencesGetInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiScmGitReferencesGetInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsScmGitReferences** | **[]string** | the fields to include for returned resources of type scmGitReferences | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**ScmGitReferenceResponse**](ScmGitReferenceResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

