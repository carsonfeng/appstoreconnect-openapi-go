# \InAppPurchaseSubmissionsApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**InAppPurchaseSubmissionsCreateInstance**](InAppPurchaseSubmissionsApi.md#InAppPurchaseSubmissionsCreateInstance) | **Post** /v1/inAppPurchaseSubmissions | 



## InAppPurchaseSubmissionsCreateInstance

> InAppPurchaseSubmissionResponse InAppPurchaseSubmissionsCreateInstance(ctx).InAppPurchaseSubmissionCreateRequest(inAppPurchaseSubmissionCreateRequest).Execute()



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
    inAppPurchaseSubmissionCreateRequest := *openapiclient.NewInAppPurchaseSubmissionCreateRequest(*openapiclient.NewInAppPurchaseSubmissionCreateRequestData("Type_example", *openapiclient.NewInAppPurchaseAppStoreReviewScreenshotCreateRequestDataRelationships(*openapiclient.NewInAppPurchaseAppStoreReviewScreenshotCreateRequestDataRelationshipsInAppPurchaseV2(*openapiclient.NewAppRelationshipsInAppPurchasesDataInner("Type_example", "Id_example"))))) // InAppPurchaseSubmissionCreateRequest | InAppPurchaseSubmission representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.InAppPurchaseSubmissionsApi.InAppPurchaseSubmissionsCreateInstance(context.Background()).InAppPurchaseSubmissionCreateRequest(inAppPurchaseSubmissionCreateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `InAppPurchaseSubmissionsApi.InAppPurchaseSubmissionsCreateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `InAppPurchaseSubmissionsCreateInstance`: InAppPurchaseSubmissionResponse
    fmt.Fprintf(os.Stdout, "Response from `InAppPurchaseSubmissionsApi.InAppPurchaseSubmissionsCreateInstance`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiInAppPurchaseSubmissionsCreateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **inAppPurchaseSubmissionCreateRequest** | [**InAppPurchaseSubmissionCreateRequest**](InAppPurchaseSubmissionCreateRequest.md) | InAppPurchaseSubmission representation | 

### Return type

[**InAppPurchaseSubmissionResponse**](InAppPurchaseSubmissionResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

