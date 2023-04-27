# \AppEventScreenshotsApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**AppEventScreenshotsCreateInstance**](AppEventScreenshotsApi.md#AppEventScreenshotsCreateInstance) | **Post** /v1/appEventScreenshots | 
[**AppEventScreenshotsDeleteInstance**](AppEventScreenshotsApi.md#AppEventScreenshotsDeleteInstance) | **Delete** /v1/appEventScreenshots/{id} | 
[**AppEventScreenshotsGetInstance**](AppEventScreenshotsApi.md#AppEventScreenshotsGetInstance) | **Get** /v1/appEventScreenshots/{id} | 
[**AppEventScreenshotsUpdateInstance**](AppEventScreenshotsApi.md#AppEventScreenshotsUpdateInstance) | **Patch** /v1/appEventScreenshots/{id} | 



## AppEventScreenshotsCreateInstance

> AppEventScreenshotResponse AppEventScreenshotsCreateInstance(ctx).AppEventScreenshotCreateRequest(appEventScreenshotCreateRequest).Execute()



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
    appEventScreenshotCreateRequest := *openapiclient.NewAppEventScreenshotCreateRequest(*openapiclient.NewAppEventScreenshotCreateRequestData("Type_example", *openapiclient.NewAppEventScreenshotCreateRequestDataAttributes(int32(123), "FileName_example", openapiclient.AppEventAssetType("EVENT_CARD")), *openapiclient.NewAppEventScreenshotCreateRequestDataRelationships(*openapiclient.NewAppEventScreenshotCreateRequestDataRelationshipsAppEventLocalization(*openapiclient.NewAppEventScreenshotRelationshipsAppEventLocalizationData("Type_example", "Id_example"))))) // AppEventScreenshotCreateRequest | AppEventScreenshot representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppEventScreenshotsApi.AppEventScreenshotsCreateInstance(context.Background()).AppEventScreenshotCreateRequest(appEventScreenshotCreateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppEventScreenshotsApi.AppEventScreenshotsCreateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppEventScreenshotsCreateInstance`: AppEventScreenshotResponse
    fmt.Fprintf(os.Stdout, "Response from `AppEventScreenshotsApi.AppEventScreenshotsCreateInstance`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiAppEventScreenshotsCreateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **appEventScreenshotCreateRequest** | [**AppEventScreenshotCreateRequest**](AppEventScreenshotCreateRequest.md) | AppEventScreenshot representation | 

### Return type

[**AppEventScreenshotResponse**](AppEventScreenshotResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppEventScreenshotsDeleteInstance

> AppEventScreenshotsDeleteInstance(ctx, id).Execute()



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
    r, err := apiClient.AppEventScreenshotsApi.AppEventScreenshotsDeleteInstance(context.Background(), id).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppEventScreenshotsApi.AppEventScreenshotsDeleteInstance``: %v\n", err)
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

Other parameters are passed through a pointer to a apiAppEventScreenshotsDeleteInstanceRequest struct via the builder pattern


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


## AppEventScreenshotsGetInstance

> AppEventScreenshotResponse AppEventScreenshotsGetInstance(ctx, id).FieldsAppEventScreenshots(fieldsAppEventScreenshots).Include(include).Execute()



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
    fieldsAppEventScreenshots := []string{"FieldsAppEventScreenshots_example"} // []string | the fields to include for returned resources of type appEventScreenshots (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppEventScreenshotsApi.AppEventScreenshotsGetInstance(context.Background(), id).FieldsAppEventScreenshots(fieldsAppEventScreenshots).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppEventScreenshotsApi.AppEventScreenshotsGetInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppEventScreenshotsGetInstance`: AppEventScreenshotResponse
    fmt.Fprintf(os.Stdout, "Response from `AppEventScreenshotsApi.AppEventScreenshotsGetInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppEventScreenshotsGetInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsAppEventScreenshots** | **[]string** | the fields to include for returned resources of type appEventScreenshots | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**AppEventScreenshotResponse**](AppEventScreenshotResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppEventScreenshotsUpdateInstance

> AppEventScreenshotResponse AppEventScreenshotsUpdateInstance(ctx, id).AppEventScreenshotUpdateRequest(appEventScreenshotUpdateRequest).Execute()



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
    appEventScreenshotUpdateRequest := *openapiclient.NewAppEventScreenshotUpdateRequest(*openapiclient.NewAppEventScreenshotUpdateRequestData("Type_example", "Id_example")) // AppEventScreenshotUpdateRequest | AppEventScreenshot representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppEventScreenshotsApi.AppEventScreenshotsUpdateInstance(context.Background(), id).AppEventScreenshotUpdateRequest(appEventScreenshotUpdateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppEventScreenshotsApi.AppEventScreenshotsUpdateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppEventScreenshotsUpdateInstance`: AppEventScreenshotResponse
    fmt.Fprintf(os.Stdout, "Response from `AppEventScreenshotsApi.AppEventScreenshotsUpdateInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppEventScreenshotsUpdateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **appEventScreenshotUpdateRequest** | [**AppEventScreenshotUpdateRequest**](AppEventScreenshotUpdateRequest.md) | AppEventScreenshot representation | 

### Return type

[**AppEventScreenshotResponse**](AppEventScreenshotResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

