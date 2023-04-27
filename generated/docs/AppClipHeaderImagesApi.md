# \AppClipHeaderImagesApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**AppClipHeaderImagesCreateInstance**](AppClipHeaderImagesApi.md#AppClipHeaderImagesCreateInstance) | **Post** /v1/appClipHeaderImages | 
[**AppClipHeaderImagesDeleteInstance**](AppClipHeaderImagesApi.md#AppClipHeaderImagesDeleteInstance) | **Delete** /v1/appClipHeaderImages/{id} | 
[**AppClipHeaderImagesGetInstance**](AppClipHeaderImagesApi.md#AppClipHeaderImagesGetInstance) | **Get** /v1/appClipHeaderImages/{id} | 
[**AppClipHeaderImagesUpdateInstance**](AppClipHeaderImagesApi.md#AppClipHeaderImagesUpdateInstance) | **Patch** /v1/appClipHeaderImages/{id} | 



## AppClipHeaderImagesCreateInstance

> AppClipHeaderImageResponse AppClipHeaderImagesCreateInstance(ctx).AppClipHeaderImageCreateRequest(appClipHeaderImageCreateRequest).Execute()



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
    appClipHeaderImageCreateRequest := *openapiclient.NewAppClipHeaderImageCreateRequest(*openapiclient.NewAppClipHeaderImageCreateRequestData("Type_example", *openapiclient.NewAppClipAdvancedExperienceImageCreateRequestDataAttributes(int32(123), "FileName_example"), *openapiclient.NewAppClipHeaderImageCreateRequestDataRelationships(*openapiclient.NewAppClipHeaderImageCreateRequestDataRelationshipsAppClipDefaultExperienceLocalization(*openapiclient.NewAppClipDefaultExperienceRelationshipsAppClipDefaultExperienceLocalizationsDataInner("Type_example", "Id_example"))))) // AppClipHeaderImageCreateRequest | AppClipHeaderImage representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppClipHeaderImagesApi.AppClipHeaderImagesCreateInstance(context.Background()).AppClipHeaderImageCreateRequest(appClipHeaderImageCreateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppClipHeaderImagesApi.AppClipHeaderImagesCreateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppClipHeaderImagesCreateInstance`: AppClipHeaderImageResponse
    fmt.Fprintf(os.Stdout, "Response from `AppClipHeaderImagesApi.AppClipHeaderImagesCreateInstance`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiAppClipHeaderImagesCreateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **appClipHeaderImageCreateRequest** | [**AppClipHeaderImageCreateRequest**](AppClipHeaderImageCreateRequest.md) | AppClipHeaderImage representation | 

### Return type

[**AppClipHeaderImageResponse**](AppClipHeaderImageResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppClipHeaderImagesDeleteInstance

> AppClipHeaderImagesDeleteInstance(ctx, id).Execute()



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
    r, err := apiClient.AppClipHeaderImagesApi.AppClipHeaderImagesDeleteInstance(context.Background(), id).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppClipHeaderImagesApi.AppClipHeaderImagesDeleteInstance``: %v\n", err)
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

Other parameters are passed through a pointer to a apiAppClipHeaderImagesDeleteInstanceRequest struct via the builder pattern


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


## AppClipHeaderImagesGetInstance

> AppClipHeaderImageResponse AppClipHeaderImagesGetInstance(ctx, id).FieldsAppClipHeaderImages(fieldsAppClipHeaderImages).Include(include).Execute()



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
    fieldsAppClipHeaderImages := []string{"FieldsAppClipHeaderImages_example"} // []string | the fields to include for returned resources of type appClipHeaderImages (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppClipHeaderImagesApi.AppClipHeaderImagesGetInstance(context.Background(), id).FieldsAppClipHeaderImages(fieldsAppClipHeaderImages).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppClipHeaderImagesApi.AppClipHeaderImagesGetInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppClipHeaderImagesGetInstance`: AppClipHeaderImageResponse
    fmt.Fprintf(os.Stdout, "Response from `AppClipHeaderImagesApi.AppClipHeaderImagesGetInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppClipHeaderImagesGetInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsAppClipHeaderImages** | **[]string** | the fields to include for returned resources of type appClipHeaderImages | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**AppClipHeaderImageResponse**](AppClipHeaderImageResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppClipHeaderImagesUpdateInstance

> AppClipHeaderImageResponse AppClipHeaderImagesUpdateInstance(ctx, id).AppClipHeaderImageUpdateRequest(appClipHeaderImageUpdateRequest).Execute()



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
    appClipHeaderImageUpdateRequest := *openapiclient.NewAppClipHeaderImageUpdateRequest(*openapiclient.NewAppClipHeaderImageUpdateRequestData("Type_example", "Id_example")) // AppClipHeaderImageUpdateRequest | AppClipHeaderImage representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppClipHeaderImagesApi.AppClipHeaderImagesUpdateInstance(context.Background(), id).AppClipHeaderImageUpdateRequest(appClipHeaderImageUpdateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppClipHeaderImagesApi.AppClipHeaderImagesUpdateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppClipHeaderImagesUpdateInstance`: AppClipHeaderImageResponse
    fmt.Fprintf(os.Stdout, "Response from `AppClipHeaderImagesApi.AppClipHeaderImagesUpdateInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppClipHeaderImagesUpdateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **appClipHeaderImageUpdateRequest** | [**AppClipHeaderImageUpdateRequest**](AppClipHeaderImageUpdateRequest.md) | AppClipHeaderImage representation | 

### Return type

[**AppClipHeaderImageResponse**](AppClipHeaderImageResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

