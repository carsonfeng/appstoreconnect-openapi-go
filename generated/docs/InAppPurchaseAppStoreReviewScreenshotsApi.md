# \InAppPurchaseAppStoreReviewScreenshotsApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**InAppPurchaseAppStoreReviewScreenshotsCreateInstance**](InAppPurchaseAppStoreReviewScreenshotsApi.md#InAppPurchaseAppStoreReviewScreenshotsCreateInstance) | **Post** /v1/inAppPurchaseAppStoreReviewScreenshots | 
[**InAppPurchaseAppStoreReviewScreenshotsDeleteInstance**](InAppPurchaseAppStoreReviewScreenshotsApi.md#InAppPurchaseAppStoreReviewScreenshotsDeleteInstance) | **Delete** /v1/inAppPurchaseAppStoreReviewScreenshots/{id} | 
[**InAppPurchaseAppStoreReviewScreenshotsGetInstance**](InAppPurchaseAppStoreReviewScreenshotsApi.md#InAppPurchaseAppStoreReviewScreenshotsGetInstance) | **Get** /v1/inAppPurchaseAppStoreReviewScreenshots/{id} | 
[**InAppPurchaseAppStoreReviewScreenshotsUpdateInstance**](InAppPurchaseAppStoreReviewScreenshotsApi.md#InAppPurchaseAppStoreReviewScreenshotsUpdateInstance) | **Patch** /v1/inAppPurchaseAppStoreReviewScreenshots/{id} | 



## InAppPurchaseAppStoreReviewScreenshotsCreateInstance

> InAppPurchaseAppStoreReviewScreenshotResponse InAppPurchaseAppStoreReviewScreenshotsCreateInstance(ctx).InAppPurchaseAppStoreReviewScreenshotCreateRequest(inAppPurchaseAppStoreReviewScreenshotCreateRequest).Execute()



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
    inAppPurchaseAppStoreReviewScreenshotCreateRequest := *openapiclient.NewInAppPurchaseAppStoreReviewScreenshotCreateRequest(*openapiclient.NewInAppPurchaseAppStoreReviewScreenshotCreateRequestData("Type_example", *openapiclient.NewAppClipAdvancedExperienceImageCreateRequestDataAttributes(int32(123), "FileName_example"), *openapiclient.NewInAppPurchaseAppStoreReviewScreenshotCreateRequestDataRelationships(*openapiclient.NewInAppPurchaseAppStoreReviewScreenshotCreateRequestDataRelationshipsInAppPurchaseV2(*openapiclient.NewAppRelationshipsInAppPurchasesDataInner("Type_example", "Id_example"))))) // InAppPurchaseAppStoreReviewScreenshotCreateRequest | InAppPurchaseAppStoreReviewScreenshot representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.InAppPurchaseAppStoreReviewScreenshotsApi.InAppPurchaseAppStoreReviewScreenshotsCreateInstance(context.Background()).InAppPurchaseAppStoreReviewScreenshotCreateRequest(inAppPurchaseAppStoreReviewScreenshotCreateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `InAppPurchaseAppStoreReviewScreenshotsApi.InAppPurchaseAppStoreReviewScreenshotsCreateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `InAppPurchaseAppStoreReviewScreenshotsCreateInstance`: InAppPurchaseAppStoreReviewScreenshotResponse
    fmt.Fprintf(os.Stdout, "Response from `InAppPurchaseAppStoreReviewScreenshotsApi.InAppPurchaseAppStoreReviewScreenshotsCreateInstance`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiInAppPurchaseAppStoreReviewScreenshotsCreateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **inAppPurchaseAppStoreReviewScreenshotCreateRequest** | [**InAppPurchaseAppStoreReviewScreenshotCreateRequest**](InAppPurchaseAppStoreReviewScreenshotCreateRequest.md) | InAppPurchaseAppStoreReviewScreenshot representation | 

### Return type

[**InAppPurchaseAppStoreReviewScreenshotResponse**](InAppPurchaseAppStoreReviewScreenshotResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## InAppPurchaseAppStoreReviewScreenshotsDeleteInstance

> InAppPurchaseAppStoreReviewScreenshotsDeleteInstance(ctx, id).Execute()



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
    r, err := apiClient.InAppPurchaseAppStoreReviewScreenshotsApi.InAppPurchaseAppStoreReviewScreenshotsDeleteInstance(context.Background(), id).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `InAppPurchaseAppStoreReviewScreenshotsApi.InAppPurchaseAppStoreReviewScreenshotsDeleteInstance``: %v\n", err)
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

Other parameters are passed through a pointer to a apiInAppPurchaseAppStoreReviewScreenshotsDeleteInstanceRequest struct via the builder pattern


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


## InAppPurchaseAppStoreReviewScreenshotsGetInstance

> InAppPurchaseAppStoreReviewScreenshotResponse InAppPurchaseAppStoreReviewScreenshotsGetInstance(ctx, id).FieldsInAppPurchaseAppStoreReviewScreenshots(fieldsInAppPurchaseAppStoreReviewScreenshots).Include(include).Execute()



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
    fieldsInAppPurchaseAppStoreReviewScreenshots := []string{"FieldsInAppPurchaseAppStoreReviewScreenshots_example"} // []string | the fields to include for returned resources of type inAppPurchaseAppStoreReviewScreenshots (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.InAppPurchaseAppStoreReviewScreenshotsApi.InAppPurchaseAppStoreReviewScreenshotsGetInstance(context.Background(), id).FieldsInAppPurchaseAppStoreReviewScreenshots(fieldsInAppPurchaseAppStoreReviewScreenshots).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `InAppPurchaseAppStoreReviewScreenshotsApi.InAppPurchaseAppStoreReviewScreenshotsGetInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `InAppPurchaseAppStoreReviewScreenshotsGetInstance`: InAppPurchaseAppStoreReviewScreenshotResponse
    fmt.Fprintf(os.Stdout, "Response from `InAppPurchaseAppStoreReviewScreenshotsApi.InAppPurchaseAppStoreReviewScreenshotsGetInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiInAppPurchaseAppStoreReviewScreenshotsGetInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsInAppPurchaseAppStoreReviewScreenshots** | **[]string** | the fields to include for returned resources of type inAppPurchaseAppStoreReviewScreenshots | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**InAppPurchaseAppStoreReviewScreenshotResponse**](InAppPurchaseAppStoreReviewScreenshotResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## InAppPurchaseAppStoreReviewScreenshotsUpdateInstance

> InAppPurchaseAppStoreReviewScreenshotResponse InAppPurchaseAppStoreReviewScreenshotsUpdateInstance(ctx, id).InAppPurchaseAppStoreReviewScreenshotUpdateRequest(inAppPurchaseAppStoreReviewScreenshotUpdateRequest).Execute()



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
    inAppPurchaseAppStoreReviewScreenshotUpdateRequest := *openapiclient.NewInAppPurchaseAppStoreReviewScreenshotUpdateRequest(*openapiclient.NewInAppPurchaseAppStoreReviewScreenshotUpdateRequestData("Type_example", "Id_example")) // InAppPurchaseAppStoreReviewScreenshotUpdateRequest | InAppPurchaseAppStoreReviewScreenshot representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.InAppPurchaseAppStoreReviewScreenshotsApi.InAppPurchaseAppStoreReviewScreenshotsUpdateInstance(context.Background(), id).InAppPurchaseAppStoreReviewScreenshotUpdateRequest(inAppPurchaseAppStoreReviewScreenshotUpdateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `InAppPurchaseAppStoreReviewScreenshotsApi.InAppPurchaseAppStoreReviewScreenshotsUpdateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `InAppPurchaseAppStoreReviewScreenshotsUpdateInstance`: InAppPurchaseAppStoreReviewScreenshotResponse
    fmt.Fprintf(os.Stdout, "Response from `InAppPurchaseAppStoreReviewScreenshotsApi.InAppPurchaseAppStoreReviewScreenshotsUpdateInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiInAppPurchaseAppStoreReviewScreenshotsUpdateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **inAppPurchaseAppStoreReviewScreenshotUpdateRequest** | [**InAppPurchaseAppStoreReviewScreenshotUpdateRequest**](InAppPurchaseAppStoreReviewScreenshotUpdateRequest.md) | InAppPurchaseAppStoreReviewScreenshot representation | 

### Return type

[**InAppPurchaseAppStoreReviewScreenshotResponse**](InAppPurchaseAppStoreReviewScreenshotResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

