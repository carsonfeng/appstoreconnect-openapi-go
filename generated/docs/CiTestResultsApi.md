# \CiTestResultsApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**CiTestResultsGetInstance**](CiTestResultsApi.md#CiTestResultsGetInstance) | **Get** /v1/ciTestResults/{id} | 



## CiTestResultsGetInstance

> CiTestResultResponse CiTestResultsGetInstance(ctx, id).FieldsCiTestResults(fieldsCiTestResults).Execute()



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
    fieldsCiTestResults := []string{"FieldsCiTestResults_example"} // []string | the fields to include for returned resources of type ciTestResults (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.CiTestResultsApi.CiTestResultsGetInstance(context.Background(), id).FieldsCiTestResults(fieldsCiTestResults).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `CiTestResultsApi.CiTestResultsGetInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `CiTestResultsGetInstance`: CiTestResultResponse
    fmt.Fprintf(os.Stdout, "Response from `CiTestResultsApi.CiTestResultsGetInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiCiTestResultsGetInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsCiTestResults** | **[]string** | the fields to include for returned resources of type ciTestResults | 

### Return type

[**CiTestResultResponse**](CiTestResultResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

