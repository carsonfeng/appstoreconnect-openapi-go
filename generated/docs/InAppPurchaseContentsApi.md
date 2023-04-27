# \InAppPurchaseContentsApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**InAppPurchaseContentsGetInstance**](InAppPurchaseContentsApi.md#InAppPurchaseContentsGetInstance) | **Get** /v1/inAppPurchaseContents/{id} | 



## InAppPurchaseContentsGetInstance

> InAppPurchaseContentResponse InAppPurchaseContentsGetInstance(ctx, id).FieldsInAppPurchaseContents(fieldsInAppPurchaseContents).Include(include).Execute()



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
    fieldsInAppPurchaseContents := []string{"FieldsInAppPurchaseContents_example"} // []string | the fields to include for returned resources of type inAppPurchaseContents (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.InAppPurchaseContentsApi.InAppPurchaseContentsGetInstance(context.Background(), id).FieldsInAppPurchaseContents(fieldsInAppPurchaseContents).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `InAppPurchaseContentsApi.InAppPurchaseContentsGetInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `InAppPurchaseContentsGetInstance`: InAppPurchaseContentResponse
    fmt.Fprintf(os.Stdout, "Response from `InAppPurchaseContentsApi.InAppPurchaseContentsGetInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiInAppPurchaseContentsGetInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsInAppPurchaseContents** | **[]string** | the fields to include for returned resources of type inAppPurchaseContents | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**InAppPurchaseContentResponse**](InAppPurchaseContentResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

