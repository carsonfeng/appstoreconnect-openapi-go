# \SubscriptionGroupSubmissionsApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**SubscriptionGroupSubmissionsCreateInstance**](SubscriptionGroupSubmissionsApi.md#SubscriptionGroupSubmissionsCreateInstance) | **Post** /v1/subscriptionGroupSubmissions | 



## SubscriptionGroupSubmissionsCreateInstance

> SubscriptionGroupSubmissionResponse SubscriptionGroupSubmissionsCreateInstance(ctx).SubscriptionGroupSubmissionCreateRequest(subscriptionGroupSubmissionCreateRequest).Execute()



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
    subscriptionGroupSubmissionCreateRequest := *openapiclient.NewSubscriptionGroupSubmissionCreateRequest(*openapiclient.NewSubscriptionGroupSubmissionCreateRequestData("Type_example", *openapiclient.NewSubscriptionGroupLocalizationCreateRequestDataRelationships(*openapiclient.NewSubscriptionGroupLocalizationCreateRequestDataRelationshipsSubscriptionGroup(*openapiclient.NewAppRelationshipsSubscriptionGroupsDataInner("Type_example", "Id_example"))))) // SubscriptionGroupSubmissionCreateRequest | SubscriptionGroupSubmission representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.SubscriptionGroupSubmissionsApi.SubscriptionGroupSubmissionsCreateInstance(context.Background()).SubscriptionGroupSubmissionCreateRequest(subscriptionGroupSubmissionCreateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `SubscriptionGroupSubmissionsApi.SubscriptionGroupSubmissionsCreateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `SubscriptionGroupSubmissionsCreateInstance`: SubscriptionGroupSubmissionResponse
    fmt.Fprintf(os.Stdout, "Response from `SubscriptionGroupSubmissionsApi.SubscriptionGroupSubmissionsCreateInstance`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiSubscriptionGroupSubmissionsCreateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **subscriptionGroupSubmissionCreateRequest** | [**SubscriptionGroupSubmissionCreateRequest**](SubscriptionGroupSubmissionCreateRequest.md) | SubscriptionGroupSubmission representation | 

### Return type

[**SubscriptionGroupSubmissionResponse**](SubscriptionGroupSubmissionResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

