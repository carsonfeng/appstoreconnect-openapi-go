# \AppClipAppStoreReviewDetailsApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**AppClipAppStoreReviewDetailsCreateInstance**](AppClipAppStoreReviewDetailsApi.md#AppClipAppStoreReviewDetailsCreateInstance) | **Post** /v1/appClipAppStoreReviewDetails | 
[**AppClipAppStoreReviewDetailsGetInstance**](AppClipAppStoreReviewDetailsApi.md#AppClipAppStoreReviewDetailsGetInstance) | **Get** /v1/appClipAppStoreReviewDetails/{id} | 
[**AppClipAppStoreReviewDetailsUpdateInstance**](AppClipAppStoreReviewDetailsApi.md#AppClipAppStoreReviewDetailsUpdateInstance) | **Patch** /v1/appClipAppStoreReviewDetails/{id} | 



## AppClipAppStoreReviewDetailsCreateInstance

> AppClipAppStoreReviewDetailResponse AppClipAppStoreReviewDetailsCreateInstance(ctx).AppClipAppStoreReviewDetailCreateRequest(appClipAppStoreReviewDetailCreateRequest).Execute()



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
    appClipAppStoreReviewDetailCreateRequest := *openapiclient.NewAppClipAppStoreReviewDetailCreateRequest(*openapiclient.NewAppClipAppStoreReviewDetailCreateRequestData("Type_example", *openapiclient.NewAppClipAppStoreReviewDetailCreateRequestDataRelationships(*openapiclient.NewAppClipAppStoreReviewDetailCreateRequestDataRelationshipsAppClipDefaultExperience(*openapiclient.NewAppClipAppStoreReviewDetailRelationshipsAppClipDefaultExperienceData("Type_example", "Id_example"))))) // AppClipAppStoreReviewDetailCreateRequest | AppClipAppStoreReviewDetail representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppClipAppStoreReviewDetailsApi.AppClipAppStoreReviewDetailsCreateInstance(context.Background()).AppClipAppStoreReviewDetailCreateRequest(appClipAppStoreReviewDetailCreateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppClipAppStoreReviewDetailsApi.AppClipAppStoreReviewDetailsCreateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppClipAppStoreReviewDetailsCreateInstance`: AppClipAppStoreReviewDetailResponse
    fmt.Fprintf(os.Stdout, "Response from `AppClipAppStoreReviewDetailsApi.AppClipAppStoreReviewDetailsCreateInstance`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiAppClipAppStoreReviewDetailsCreateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **appClipAppStoreReviewDetailCreateRequest** | [**AppClipAppStoreReviewDetailCreateRequest**](AppClipAppStoreReviewDetailCreateRequest.md) | AppClipAppStoreReviewDetail representation | 

### Return type

[**AppClipAppStoreReviewDetailResponse**](AppClipAppStoreReviewDetailResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppClipAppStoreReviewDetailsGetInstance

> AppClipAppStoreReviewDetailResponse AppClipAppStoreReviewDetailsGetInstance(ctx, id).FieldsAppClipAppStoreReviewDetails(fieldsAppClipAppStoreReviewDetails).Include(include).Execute()



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
    fieldsAppClipAppStoreReviewDetails := []string{"FieldsAppClipAppStoreReviewDetails_example"} // []string | the fields to include for returned resources of type appClipAppStoreReviewDetails (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppClipAppStoreReviewDetailsApi.AppClipAppStoreReviewDetailsGetInstance(context.Background(), id).FieldsAppClipAppStoreReviewDetails(fieldsAppClipAppStoreReviewDetails).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppClipAppStoreReviewDetailsApi.AppClipAppStoreReviewDetailsGetInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppClipAppStoreReviewDetailsGetInstance`: AppClipAppStoreReviewDetailResponse
    fmt.Fprintf(os.Stdout, "Response from `AppClipAppStoreReviewDetailsApi.AppClipAppStoreReviewDetailsGetInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppClipAppStoreReviewDetailsGetInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsAppClipAppStoreReviewDetails** | **[]string** | the fields to include for returned resources of type appClipAppStoreReviewDetails | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**AppClipAppStoreReviewDetailResponse**](AppClipAppStoreReviewDetailResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppClipAppStoreReviewDetailsUpdateInstance

> AppClipAppStoreReviewDetailResponse AppClipAppStoreReviewDetailsUpdateInstance(ctx, id).AppClipAppStoreReviewDetailUpdateRequest(appClipAppStoreReviewDetailUpdateRequest).Execute()



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
    appClipAppStoreReviewDetailUpdateRequest := *openapiclient.NewAppClipAppStoreReviewDetailUpdateRequest(*openapiclient.NewAppClipAppStoreReviewDetailUpdateRequestData("Type_example", "Id_example")) // AppClipAppStoreReviewDetailUpdateRequest | AppClipAppStoreReviewDetail representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppClipAppStoreReviewDetailsApi.AppClipAppStoreReviewDetailsUpdateInstance(context.Background(), id).AppClipAppStoreReviewDetailUpdateRequest(appClipAppStoreReviewDetailUpdateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppClipAppStoreReviewDetailsApi.AppClipAppStoreReviewDetailsUpdateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppClipAppStoreReviewDetailsUpdateInstance`: AppClipAppStoreReviewDetailResponse
    fmt.Fprintf(os.Stdout, "Response from `AppClipAppStoreReviewDetailsApi.AppClipAppStoreReviewDetailsUpdateInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppClipAppStoreReviewDetailsUpdateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **appClipAppStoreReviewDetailUpdateRequest** | [**AppClipAppStoreReviewDetailUpdateRequest**](AppClipAppStoreReviewDetailUpdateRequest.md) | AppClipAppStoreReviewDetail representation | 

### Return type

[**AppClipAppStoreReviewDetailResponse**](AppClipAppStoreReviewDetailResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

