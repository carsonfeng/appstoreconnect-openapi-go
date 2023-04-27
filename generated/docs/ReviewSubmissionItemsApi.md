# \ReviewSubmissionItemsApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**ReviewSubmissionItemsCreateInstance**](ReviewSubmissionItemsApi.md#ReviewSubmissionItemsCreateInstance) | **Post** /v1/reviewSubmissionItems | 
[**ReviewSubmissionItemsDeleteInstance**](ReviewSubmissionItemsApi.md#ReviewSubmissionItemsDeleteInstance) | **Delete** /v1/reviewSubmissionItems/{id} | 
[**ReviewSubmissionItemsUpdateInstance**](ReviewSubmissionItemsApi.md#ReviewSubmissionItemsUpdateInstance) | **Patch** /v1/reviewSubmissionItems/{id} | 



## ReviewSubmissionItemsCreateInstance

> ReviewSubmissionItemResponse ReviewSubmissionItemsCreateInstance(ctx).ReviewSubmissionItemCreateRequest(reviewSubmissionItemCreateRequest).Execute()



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
    reviewSubmissionItemCreateRequest := *openapiclient.NewReviewSubmissionItemCreateRequest(*openapiclient.NewReviewSubmissionItemCreateRequestData("Type_example", *openapiclient.NewReviewSubmissionItemCreateRequestDataRelationships(*openapiclient.NewReviewSubmissionItemCreateRequestDataRelationshipsReviewSubmission(*openapiclient.NewAppRelationshipsReviewSubmissionsDataInner("Type_example", "Id_example"))))) // ReviewSubmissionItemCreateRequest | ReviewSubmissionItem representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.ReviewSubmissionItemsApi.ReviewSubmissionItemsCreateInstance(context.Background()).ReviewSubmissionItemCreateRequest(reviewSubmissionItemCreateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `ReviewSubmissionItemsApi.ReviewSubmissionItemsCreateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `ReviewSubmissionItemsCreateInstance`: ReviewSubmissionItemResponse
    fmt.Fprintf(os.Stdout, "Response from `ReviewSubmissionItemsApi.ReviewSubmissionItemsCreateInstance`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiReviewSubmissionItemsCreateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **reviewSubmissionItemCreateRequest** | [**ReviewSubmissionItemCreateRequest**](ReviewSubmissionItemCreateRequest.md) | ReviewSubmissionItem representation | 

### Return type

[**ReviewSubmissionItemResponse**](ReviewSubmissionItemResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## ReviewSubmissionItemsDeleteInstance

> ReviewSubmissionItemsDeleteInstance(ctx, id).Execute()



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

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    r, err := apiClient.ReviewSubmissionItemsApi.ReviewSubmissionItemsDeleteInstance(context.Background(), id).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `ReviewSubmissionItemsApi.ReviewSubmissionItemsDeleteInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiReviewSubmissionItemsDeleteInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------


### Return type

 (empty response body)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## ReviewSubmissionItemsUpdateInstance

> ReviewSubmissionItemResponse ReviewSubmissionItemsUpdateInstance(ctx, id).ReviewSubmissionItemUpdateRequest(reviewSubmissionItemUpdateRequest).Execute()



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
    reviewSubmissionItemUpdateRequest := *openapiclient.NewReviewSubmissionItemUpdateRequest(*openapiclient.NewReviewSubmissionItemUpdateRequestData("Type_example", "Id_example")) // ReviewSubmissionItemUpdateRequest | ReviewSubmissionItem representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.ReviewSubmissionItemsApi.ReviewSubmissionItemsUpdateInstance(context.Background(), id).ReviewSubmissionItemUpdateRequest(reviewSubmissionItemUpdateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `ReviewSubmissionItemsApi.ReviewSubmissionItemsUpdateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `ReviewSubmissionItemsUpdateInstance`: ReviewSubmissionItemResponse
    fmt.Fprintf(os.Stdout, "Response from `ReviewSubmissionItemsApi.ReviewSubmissionItemsUpdateInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiReviewSubmissionItemsUpdateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **reviewSubmissionItemUpdateRequest** | [**ReviewSubmissionItemUpdateRequest**](ReviewSubmissionItemUpdateRequest.md) | ReviewSubmissionItem representation | 

### Return type

[**ReviewSubmissionItemResponse**](ReviewSubmissionItemResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

