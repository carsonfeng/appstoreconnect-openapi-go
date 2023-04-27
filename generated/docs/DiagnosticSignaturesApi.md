# \DiagnosticSignaturesApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**DiagnosticSignaturesLogsGetToManyRelated**](DiagnosticSignaturesApi.md#DiagnosticSignaturesLogsGetToManyRelated) | **Get** /v1/diagnosticSignatures/{id}/logs | 



## DiagnosticSignaturesLogsGetToManyRelated

> DiagnosticLogs DiagnosticSignaturesLogsGetToManyRelated(ctx, id).Limit(limit).Execute()



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
    limit := int32(56) // int32 | maximum resources per page (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.DiagnosticSignaturesApi.DiagnosticSignaturesLogsGetToManyRelated(context.Background(), id).Limit(limit).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `DiagnosticSignaturesApi.DiagnosticSignaturesLogsGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `DiagnosticSignaturesLogsGetToManyRelated`: DiagnosticLogs
    fmt.Fprintf(os.Stdout, "Response from `DiagnosticSignaturesApi.DiagnosticSignaturesLogsGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiDiagnosticSignaturesLogsGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **limit** | **int32** | maximum resources per page | 

### Return type

[**DiagnosticLogs**](DiagnosticLogs.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json, application/vnd.apple.diagnostic-logs+json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

