# \AppClipDefaultExperienceLocalizationsApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**AppClipDefaultExperienceLocalizationsAppClipHeaderImageGetToOneRelated**](AppClipDefaultExperienceLocalizationsApi.md#AppClipDefaultExperienceLocalizationsAppClipHeaderImageGetToOneRelated) | **Get** /v1/appClipDefaultExperienceLocalizations/{id}/appClipHeaderImage | 
[**AppClipDefaultExperienceLocalizationsCreateInstance**](AppClipDefaultExperienceLocalizationsApi.md#AppClipDefaultExperienceLocalizationsCreateInstance) | **Post** /v1/appClipDefaultExperienceLocalizations | 
[**AppClipDefaultExperienceLocalizationsDeleteInstance**](AppClipDefaultExperienceLocalizationsApi.md#AppClipDefaultExperienceLocalizationsDeleteInstance) | **Delete** /v1/appClipDefaultExperienceLocalizations/{id} | 
[**AppClipDefaultExperienceLocalizationsGetInstance**](AppClipDefaultExperienceLocalizationsApi.md#AppClipDefaultExperienceLocalizationsGetInstance) | **Get** /v1/appClipDefaultExperienceLocalizations/{id} | 
[**AppClipDefaultExperienceLocalizationsUpdateInstance**](AppClipDefaultExperienceLocalizationsApi.md#AppClipDefaultExperienceLocalizationsUpdateInstance) | **Patch** /v1/appClipDefaultExperienceLocalizations/{id} | 



## AppClipDefaultExperienceLocalizationsAppClipHeaderImageGetToOneRelated

> AppClipHeaderImageResponse AppClipDefaultExperienceLocalizationsAppClipHeaderImageGetToOneRelated(ctx, id).FieldsAppClipHeaderImages(fieldsAppClipHeaderImages).FieldsAppClipDefaultExperienceLocalizations(fieldsAppClipDefaultExperienceLocalizations).Include(include).Execute()



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
    fieldsAppClipDefaultExperienceLocalizations := []string{"FieldsAppClipDefaultExperienceLocalizations_example"} // []string | the fields to include for returned resources of type appClipDefaultExperienceLocalizations (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppClipDefaultExperienceLocalizationsApi.AppClipDefaultExperienceLocalizationsAppClipHeaderImageGetToOneRelated(context.Background(), id).FieldsAppClipHeaderImages(fieldsAppClipHeaderImages).FieldsAppClipDefaultExperienceLocalizations(fieldsAppClipDefaultExperienceLocalizations).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppClipDefaultExperienceLocalizationsApi.AppClipDefaultExperienceLocalizationsAppClipHeaderImageGetToOneRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppClipDefaultExperienceLocalizationsAppClipHeaderImageGetToOneRelated`: AppClipHeaderImageResponse
    fmt.Fprintf(os.Stdout, "Response from `AppClipDefaultExperienceLocalizationsApi.AppClipDefaultExperienceLocalizationsAppClipHeaderImageGetToOneRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppClipDefaultExperienceLocalizationsAppClipHeaderImageGetToOneRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsAppClipHeaderImages** | **[]string** | the fields to include for returned resources of type appClipHeaderImages | 
 **fieldsAppClipDefaultExperienceLocalizations** | **[]string** | the fields to include for returned resources of type appClipDefaultExperienceLocalizations | 
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


## AppClipDefaultExperienceLocalizationsCreateInstance

> AppClipDefaultExperienceLocalizationResponse AppClipDefaultExperienceLocalizationsCreateInstance(ctx).AppClipDefaultExperienceLocalizationCreateRequest(appClipDefaultExperienceLocalizationCreateRequest).Execute()



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
    appClipDefaultExperienceLocalizationCreateRequest := *openapiclient.NewAppClipDefaultExperienceLocalizationCreateRequest(*openapiclient.NewAppClipDefaultExperienceLocalizationCreateRequestData("Type_example", *openapiclient.NewAppClipDefaultExperienceLocalizationCreateRequestDataAttributes("Locale_example"), *openapiclient.NewAppClipAppStoreReviewDetailCreateRequestDataRelationships(*openapiclient.NewAppClipAppStoreReviewDetailCreateRequestDataRelationshipsAppClipDefaultExperience(*openapiclient.NewAppClipAppStoreReviewDetailRelationshipsAppClipDefaultExperienceData("Type_example", "Id_example"))))) // AppClipDefaultExperienceLocalizationCreateRequest | AppClipDefaultExperienceLocalization representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppClipDefaultExperienceLocalizationsApi.AppClipDefaultExperienceLocalizationsCreateInstance(context.Background()).AppClipDefaultExperienceLocalizationCreateRequest(appClipDefaultExperienceLocalizationCreateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppClipDefaultExperienceLocalizationsApi.AppClipDefaultExperienceLocalizationsCreateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppClipDefaultExperienceLocalizationsCreateInstance`: AppClipDefaultExperienceLocalizationResponse
    fmt.Fprintf(os.Stdout, "Response from `AppClipDefaultExperienceLocalizationsApi.AppClipDefaultExperienceLocalizationsCreateInstance`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiAppClipDefaultExperienceLocalizationsCreateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **appClipDefaultExperienceLocalizationCreateRequest** | [**AppClipDefaultExperienceLocalizationCreateRequest**](AppClipDefaultExperienceLocalizationCreateRequest.md) | AppClipDefaultExperienceLocalization representation | 

### Return type

[**AppClipDefaultExperienceLocalizationResponse**](AppClipDefaultExperienceLocalizationResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppClipDefaultExperienceLocalizationsDeleteInstance

> AppClipDefaultExperienceLocalizationsDeleteInstance(ctx, id).Execute()



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
    r, err := apiClient.AppClipDefaultExperienceLocalizationsApi.AppClipDefaultExperienceLocalizationsDeleteInstance(context.Background(), id).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppClipDefaultExperienceLocalizationsApi.AppClipDefaultExperienceLocalizationsDeleteInstance``: %v\n", err)
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

Other parameters are passed through a pointer to a apiAppClipDefaultExperienceLocalizationsDeleteInstanceRequest struct via the builder pattern


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


## AppClipDefaultExperienceLocalizationsGetInstance

> AppClipDefaultExperienceLocalizationResponse AppClipDefaultExperienceLocalizationsGetInstance(ctx, id).FieldsAppClipDefaultExperienceLocalizations(fieldsAppClipDefaultExperienceLocalizations).Include(include).FieldsAppClipHeaderImages(fieldsAppClipHeaderImages).Execute()



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
    fieldsAppClipDefaultExperienceLocalizations := []string{"FieldsAppClipDefaultExperienceLocalizations_example"} // []string | the fields to include for returned resources of type appClipDefaultExperienceLocalizations (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)
    fieldsAppClipHeaderImages := []string{"FieldsAppClipHeaderImages_example"} // []string | the fields to include for returned resources of type appClipHeaderImages (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppClipDefaultExperienceLocalizationsApi.AppClipDefaultExperienceLocalizationsGetInstance(context.Background(), id).FieldsAppClipDefaultExperienceLocalizations(fieldsAppClipDefaultExperienceLocalizations).Include(include).FieldsAppClipHeaderImages(fieldsAppClipHeaderImages).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppClipDefaultExperienceLocalizationsApi.AppClipDefaultExperienceLocalizationsGetInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppClipDefaultExperienceLocalizationsGetInstance`: AppClipDefaultExperienceLocalizationResponse
    fmt.Fprintf(os.Stdout, "Response from `AppClipDefaultExperienceLocalizationsApi.AppClipDefaultExperienceLocalizationsGetInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppClipDefaultExperienceLocalizationsGetInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsAppClipDefaultExperienceLocalizations** | **[]string** | the fields to include for returned resources of type appClipDefaultExperienceLocalizations | 
 **include** | **[]string** | comma-separated list of relationships to include | 
 **fieldsAppClipHeaderImages** | **[]string** | the fields to include for returned resources of type appClipHeaderImages | 

### Return type

[**AppClipDefaultExperienceLocalizationResponse**](AppClipDefaultExperienceLocalizationResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppClipDefaultExperienceLocalizationsUpdateInstance

> AppClipDefaultExperienceLocalizationResponse AppClipDefaultExperienceLocalizationsUpdateInstance(ctx, id).AppClipDefaultExperienceLocalizationUpdateRequest(appClipDefaultExperienceLocalizationUpdateRequest).Execute()



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
    appClipDefaultExperienceLocalizationUpdateRequest := *openapiclient.NewAppClipDefaultExperienceLocalizationUpdateRequest(*openapiclient.NewAppClipDefaultExperienceLocalizationUpdateRequestData("Type_example", "Id_example")) // AppClipDefaultExperienceLocalizationUpdateRequest | AppClipDefaultExperienceLocalization representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppClipDefaultExperienceLocalizationsApi.AppClipDefaultExperienceLocalizationsUpdateInstance(context.Background(), id).AppClipDefaultExperienceLocalizationUpdateRequest(appClipDefaultExperienceLocalizationUpdateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppClipDefaultExperienceLocalizationsApi.AppClipDefaultExperienceLocalizationsUpdateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppClipDefaultExperienceLocalizationsUpdateInstance`: AppClipDefaultExperienceLocalizationResponse
    fmt.Fprintf(os.Stdout, "Response from `AppClipDefaultExperienceLocalizationsApi.AppClipDefaultExperienceLocalizationsUpdateInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppClipDefaultExperienceLocalizationsUpdateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **appClipDefaultExperienceLocalizationUpdateRequest** | [**AppClipDefaultExperienceLocalizationUpdateRequest**](AppClipDefaultExperienceLocalizationUpdateRequest.md) | AppClipDefaultExperienceLocalization representation | 

### Return type

[**AppClipDefaultExperienceLocalizationResponse**](AppClipDefaultExperienceLocalizationResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

