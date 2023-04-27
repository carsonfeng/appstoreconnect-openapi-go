# \AppEventLocalizationsApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**AppEventLocalizationsAppEventScreenshotsGetToManyRelated**](AppEventLocalizationsApi.md#AppEventLocalizationsAppEventScreenshotsGetToManyRelated) | **Get** /v1/appEventLocalizations/{id}/appEventScreenshots | 
[**AppEventLocalizationsAppEventVideoClipsGetToManyRelated**](AppEventLocalizationsApi.md#AppEventLocalizationsAppEventVideoClipsGetToManyRelated) | **Get** /v1/appEventLocalizations/{id}/appEventVideoClips | 
[**AppEventLocalizationsCreateInstance**](AppEventLocalizationsApi.md#AppEventLocalizationsCreateInstance) | **Post** /v1/appEventLocalizations | 
[**AppEventLocalizationsDeleteInstance**](AppEventLocalizationsApi.md#AppEventLocalizationsDeleteInstance) | **Delete** /v1/appEventLocalizations/{id} | 
[**AppEventLocalizationsGetInstance**](AppEventLocalizationsApi.md#AppEventLocalizationsGetInstance) | **Get** /v1/appEventLocalizations/{id} | 
[**AppEventLocalizationsUpdateInstance**](AppEventLocalizationsApi.md#AppEventLocalizationsUpdateInstance) | **Patch** /v1/appEventLocalizations/{id} | 



## AppEventLocalizationsAppEventScreenshotsGetToManyRelated

> AppEventScreenshotsResponse AppEventLocalizationsAppEventScreenshotsGetToManyRelated(ctx, id).FieldsAppEventScreenshots(fieldsAppEventScreenshots).FieldsAppEventLocalizations(fieldsAppEventLocalizations).Limit(limit).Include(include).Execute()



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
    fieldsAppEventLocalizations := []string{"FieldsAppEventLocalizations_example"} // []string | the fields to include for returned resources of type appEventLocalizations (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppEventLocalizationsApi.AppEventLocalizationsAppEventScreenshotsGetToManyRelated(context.Background(), id).FieldsAppEventScreenshots(fieldsAppEventScreenshots).FieldsAppEventLocalizations(fieldsAppEventLocalizations).Limit(limit).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppEventLocalizationsApi.AppEventLocalizationsAppEventScreenshotsGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppEventLocalizationsAppEventScreenshotsGetToManyRelated`: AppEventScreenshotsResponse
    fmt.Fprintf(os.Stdout, "Response from `AppEventLocalizationsApi.AppEventLocalizationsAppEventScreenshotsGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppEventLocalizationsAppEventScreenshotsGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsAppEventScreenshots** | **[]string** | the fields to include for returned resources of type appEventScreenshots | 
 **fieldsAppEventLocalizations** | **[]string** | the fields to include for returned resources of type appEventLocalizations | 
 **limit** | **int32** | maximum resources per page | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**AppEventScreenshotsResponse**](AppEventScreenshotsResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppEventLocalizationsAppEventVideoClipsGetToManyRelated

> AppEventVideoClipsResponse AppEventLocalizationsAppEventVideoClipsGetToManyRelated(ctx, id).FieldsAppEventVideoClips(fieldsAppEventVideoClips).FieldsAppEventLocalizations(fieldsAppEventLocalizations).Limit(limit).Include(include).Execute()



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
    fieldsAppEventLocalizations := []string{"FieldsAppEventLocalizations_example"} // []string | the fields to include for returned resources of type appEventLocalizations (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppEventLocalizationsApi.AppEventLocalizationsAppEventVideoClipsGetToManyRelated(context.Background(), id).FieldsAppEventVideoClips(fieldsAppEventVideoClips).FieldsAppEventLocalizations(fieldsAppEventLocalizations).Limit(limit).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppEventLocalizationsApi.AppEventLocalizationsAppEventVideoClipsGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppEventLocalizationsAppEventVideoClipsGetToManyRelated`: AppEventVideoClipsResponse
    fmt.Fprintf(os.Stdout, "Response from `AppEventLocalizationsApi.AppEventLocalizationsAppEventVideoClipsGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppEventLocalizationsAppEventVideoClipsGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsAppEventVideoClips** | **[]string** | the fields to include for returned resources of type appEventVideoClips | 
 **fieldsAppEventLocalizations** | **[]string** | the fields to include for returned resources of type appEventLocalizations | 
 **limit** | **int32** | maximum resources per page | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**AppEventVideoClipsResponse**](AppEventVideoClipsResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppEventLocalizationsCreateInstance

> AppEventLocalizationResponse AppEventLocalizationsCreateInstance(ctx).AppEventLocalizationCreateRequest(appEventLocalizationCreateRequest).Execute()



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
    appEventLocalizationCreateRequest := *openapiclient.NewAppEventLocalizationCreateRequest(*openapiclient.NewAppEventLocalizationCreateRequestData("Type_example", *openapiclient.NewAppEventLocalizationCreateRequestDataAttributes("Locale_example"), *openapiclient.NewAppEventLocalizationCreateRequestDataRelationships(*openapiclient.NewAppEventLocalizationCreateRequestDataRelationshipsAppEvent(*openapiclient.NewAppEventLocalizationRelationshipsAppEventData("Type_example", "Id_example"))))) // AppEventLocalizationCreateRequest | AppEventLocalization representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppEventLocalizationsApi.AppEventLocalizationsCreateInstance(context.Background()).AppEventLocalizationCreateRequest(appEventLocalizationCreateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppEventLocalizationsApi.AppEventLocalizationsCreateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppEventLocalizationsCreateInstance`: AppEventLocalizationResponse
    fmt.Fprintf(os.Stdout, "Response from `AppEventLocalizationsApi.AppEventLocalizationsCreateInstance`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiAppEventLocalizationsCreateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **appEventLocalizationCreateRequest** | [**AppEventLocalizationCreateRequest**](AppEventLocalizationCreateRequest.md) | AppEventLocalization representation | 

### Return type

[**AppEventLocalizationResponse**](AppEventLocalizationResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppEventLocalizationsDeleteInstance

> AppEventLocalizationsDeleteInstance(ctx, id).Execute()



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
    r, err := apiClient.AppEventLocalizationsApi.AppEventLocalizationsDeleteInstance(context.Background(), id).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppEventLocalizationsApi.AppEventLocalizationsDeleteInstance``: %v\n", err)
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

Other parameters are passed through a pointer to a apiAppEventLocalizationsDeleteInstanceRequest struct via the builder pattern


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


## AppEventLocalizationsGetInstance

> AppEventLocalizationResponse AppEventLocalizationsGetInstance(ctx, id).FieldsAppEventLocalizations(fieldsAppEventLocalizations).Include(include).FieldsAppEventScreenshots(fieldsAppEventScreenshots).FieldsAppEventVideoClips(fieldsAppEventVideoClips).LimitAppEventScreenshots(limitAppEventScreenshots).LimitAppEventVideoClips(limitAppEventVideoClips).Execute()



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
    fieldsAppEventLocalizations := []string{"FieldsAppEventLocalizations_example"} // []string | the fields to include for returned resources of type appEventLocalizations (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)
    fieldsAppEventScreenshots := []string{"FieldsAppEventScreenshots_example"} // []string | the fields to include for returned resources of type appEventScreenshots (optional)
    fieldsAppEventVideoClips := []string{"FieldsAppEventVideoClips_example"} // []string | the fields to include for returned resources of type appEventVideoClips (optional)
    limitAppEventScreenshots := int32(56) // int32 | maximum number of related appEventScreenshots returned (when they are included) (optional)
    limitAppEventVideoClips := int32(56) // int32 | maximum number of related appEventVideoClips returned (when they are included) (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppEventLocalizationsApi.AppEventLocalizationsGetInstance(context.Background(), id).FieldsAppEventLocalizations(fieldsAppEventLocalizations).Include(include).FieldsAppEventScreenshots(fieldsAppEventScreenshots).FieldsAppEventVideoClips(fieldsAppEventVideoClips).LimitAppEventScreenshots(limitAppEventScreenshots).LimitAppEventVideoClips(limitAppEventVideoClips).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppEventLocalizationsApi.AppEventLocalizationsGetInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppEventLocalizationsGetInstance`: AppEventLocalizationResponse
    fmt.Fprintf(os.Stdout, "Response from `AppEventLocalizationsApi.AppEventLocalizationsGetInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppEventLocalizationsGetInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsAppEventLocalizations** | **[]string** | the fields to include for returned resources of type appEventLocalizations | 
 **include** | **[]string** | comma-separated list of relationships to include | 
 **fieldsAppEventScreenshots** | **[]string** | the fields to include for returned resources of type appEventScreenshots | 
 **fieldsAppEventVideoClips** | **[]string** | the fields to include for returned resources of type appEventVideoClips | 
 **limitAppEventScreenshots** | **int32** | maximum number of related appEventScreenshots returned (when they are included) | 
 **limitAppEventVideoClips** | **int32** | maximum number of related appEventVideoClips returned (when they are included) | 

### Return type

[**AppEventLocalizationResponse**](AppEventLocalizationResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppEventLocalizationsUpdateInstance

> AppEventLocalizationResponse AppEventLocalizationsUpdateInstance(ctx, id).AppEventLocalizationUpdateRequest(appEventLocalizationUpdateRequest).Execute()



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
    appEventLocalizationUpdateRequest := *openapiclient.NewAppEventLocalizationUpdateRequest(*openapiclient.NewAppEventLocalizationUpdateRequestData("Type_example", "Id_example")) // AppEventLocalizationUpdateRequest | AppEventLocalization representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppEventLocalizationsApi.AppEventLocalizationsUpdateInstance(context.Background(), id).AppEventLocalizationUpdateRequest(appEventLocalizationUpdateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppEventLocalizationsApi.AppEventLocalizationsUpdateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppEventLocalizationsUpdateInstance`: AppEventLocalizationResponse
    fmt.Fprintf(os.Stdout, "Response from `AppEventLocalizationsApi.AppEventLocalizationsUpdateInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppEventLocalizationsUpdateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **appEventLocalizationUpdateRequest** | [**AppEventLocalizationUpdateRequest**](AppEventLocalizationUpdateRequest.md) | AppEventLocalization representation | 

### Return type

[**AppEventLocalizationResponse**](AppEventLocalizationResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

