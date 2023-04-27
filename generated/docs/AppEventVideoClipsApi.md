# \AppEventVideoClipsApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**AppEventVideoClipsCreateInstance**](AppEventVideoClipsApi.md#AppEventVideoClipsCreateInstance) | **Post** /v1/appEventVideoClips | 
[**AppEventVideoClipsDeleteInstance**](AppEventVideoClipsApi.md#AppEventVideoClipsDeleteInstance) | **Delete** /v1/appEventVideoClips/{id} | 
[**AppEventVideoClipsGetInstance**](AppEventVideoClipsApi.md#AppEventVideoClipsGetInstance) | **Get** /v1/appEventVideoClips/{id} | 
[**AppEventVideoClipsUpdateInstance**](AppEventVideoClipsApi.md#AppEventVideoClipsUpdateInstance) | **Patch** /v1/appEventVideoClips/{id} | 



## AppEventVideoClipsCreateInstance

> AppEventVideoClipResponse AppEventVideoClipsCreateInstance(ctx).AppEventVideoClipCreateRequest(appEventVideoClipCreateRequest).Execute()



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
    appEventVideoClipCreateRequest := *openapiclient.NewAppEventVideoClipCreateRequest(*openapiclient.NewAppEventVideoClipCreateRequestData("Type_example", *openapiclient.NewAppEventVideoClipCreateRequestDataAttributes(int32(123), "FileName_example", openapiclient.AppEventAssetType("EVENT_CARD")), *openapiclient.NewAppEventScreenshotCreateRequestDataRelationships(*openapiclient.NewAppEventScreenshotCreateRequestDataRelationshipsAppEventLocalization(*openapiclient.NewAppEventScreenshotRelationshipsAppEventLocalizationData("Type_example", "Id_example"))))) // AppEventVideoClipCreateRequest | AppEventVideoClip representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppEventVideoClipsApi.AppEventVideoClipsCreateInstance(context.Background()).AppEventVideoClipCreateRequest(appEventVideoClipCreateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppEventVideoClipsApi.AppEventVideoClipsCreateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppEventVideoClipsCreateInstance`: AppEventVideoClipResponse
    fmt.Fprintf(os.Stdout, "Response from `AppEventVideoClipsApi.AppEventVideoClipsCreateInstance`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiAppEventVideoClipsCreateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **appEventVideoClipCreateRequest** | [**AppEventVideoClipCreateRequest**](AppEventVideoClipCreateRequest.md) | AppEventVideoClip representation | 

### Return type

[**AppEventVideoClipResponse**](AppEventVideoClipResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppEventVideoClipsDeleteInstance

> AppEventVideoClipsDeleteInstance(ctx, id).Execute()



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
    r, err := apiClient.AppEventVideoClipsApi.AppEventVideoClipsDeleteInstance(context.Background(), id).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppEventVideoClipsApi.AppEventVideoClipsDeleteInstance``: %v\n", err)
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

Other parameters are passed through a pointer to a apiAppEventVideoClipsDeleteInstanceRequest struct via the builder pattern


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


## AppEventVideoClipsGetInstance

> AppEventVideoClipResponse AppEventVideoClipsGetInstance(ctx, id).FieldsAppEventVideoClips(fieldsAppEventVideoClips).Include(include).Execute()



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
    fieldsAppEventVideoClips := []string{"FieldsAppEventVideoClips_example"} // []string | the fields to include for returned resources of type appEventVideoClips (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppEventVideoClipsApi.AppEventVideoClipsGetInstance(context.Background(), id).FieldsAppEventVideoClips(fieldsAppEventVideoClips).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppEventVideoClipsApi.AppEventVideoClipsGetInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppEventVideoClipsGetInstance`: AppEventVideoClipResponse
    fmt.Fprintf(os.Stdout, "Response from `AppEventVideoClipsApi.AppEventVideoClipsGetInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppEventVideoClipsGetInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsAppEventVideoClips** | **[]string** | the fields to include for returned resources of type appEventVideoClips | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**AppEventVideoClipResponse**](AppEventVideoClipResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppEventVideoClipsUpdateInstance

> AppEventVideoClipResponse AppEventVideoClipsUpdateInstance(ctx, id).AppEventVideoClipUpdateRequest(appEventVideoClipUpdateRequest).Execute()



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
    appEventVideoClipUpdateRequest := *openapiclient.NewAppEventVideoClipUpdateRequest(*openapiclient.NewAppEventVideoClipUpdateRequestData("Type_example", "Id_example")) // AppEventVideoClipUpdateRequest | AppEventVideoClip representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppEventVideoClipsApi.AppEventVideoClipsUpdateInstance(context.Background(), id).AppEventVideoClipUpdateRequest(appEventVideoClipUpdateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppEventVideoClipsApi.AppEventVideoClipsUpdateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppEventVideoClipsUpdateInstance`: AppEventVideoClipResponse
    fmt.Fprintf(os.Stdout, "Response from `AppEventVideoClipsApi.AppEventVideoClipsUpdateInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppEventVideoClipsUpdateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **appEventVideoClipUpdateRequest** | [**AppEventVideoClipUpdateRequest**](AppEventVideoClipUpdateRequest.md) | AppEventVideoClip representation | 

### Return type

[**AppEventVideoClipResponse**](AppEventVideoClipResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

