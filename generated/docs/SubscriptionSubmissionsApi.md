# \SubscriptionSubmissionsApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**SubscriptionSubmissionsCreateInstance**](SubscriptionSubmissionsApi.md#SubscriptionSubmissionsCreateInstance) | **Post** /v1/subscriptionSubmissions | 



## SubscriptionSubmissionsCreateInstance

> SubscriptionSubmissionResponse SubscriptionSubmissionsCreateInstance(ctx).SubscriptionSubmissionCreateRequest(subscriptionSubmissionCreateRequest).Execute()



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
    subscriptionSubmissionCreateRequest := *openapiclient.NewSubscriptionSubmissionCreateRequest(*openapiclient.NewSubscriptionSubmissionCreateRequestData("Type_example", *openapiclient.NewSubscriptionAppStoreReviewScreenshotCreateRequestDataRelationships(*openapiclient.NewSubscriptionAppStoreReviewScreenshotCreateRequestDataRelationshipsSubscription(*openapiclient.NewPromotedPurchaseRelationshipsSubscriptionData("Type_example", "Id_example"))))) // SubscriptionSubmissionCreateRequest | SubscriptionSubmission representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.SubscriptionSubmissionsApi.SubscriptionSubmissionsCreateInstance(context.Background()).SubscriptionSubmissionCreateRequest(subscriptionSubmissionCreateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `SubscriptionSubmissionsApi.SubscriptionSubmissionsCreateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `SubscriptionSubmissionsCreateInstance`: SubscriptionSubmissionResponse
    fmt.Fprintf(os.Stdout, "Response from `SubscriptionSubmissionsApi.SubscriptionSubmissionsCreateInstance`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiSubscriptionSubmissionsCreateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **subscriptionSubmissionCreateRequest** | [**SubscriptionSubmissionCreateRequest**](SubscriptionSubmissionCreateRequest.md) | SubscriptionSubmission representation | 

### Return type

[**SubscriptionSubmissionResponse**](SubscriptionSubmissionResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

