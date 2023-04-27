# \AppClipAdvancedExperiencesApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**AppClipAdvancedExperiencesCreateInstance**](AppClipAdvancedExperiencesApi.md#AppClipAdvancedExperiencesCreateInstance) | **Post** /v1/appClipAdvancedExperiences | 
[**AppClipAdvancedExperiencesGetInstance**](AppClipAdvancedExperiencesApi.md#AppClipAdvancedExperiencesGetInstance) | **Get** /v1/appClipAdvancedExperiences/{id} | 
[**AppClipAdvancedExperiencesUpdateInstance**](AppClipAdvancedExperiencesApi.md#AppClipAdvancedExperiencesUpdateInstance) | **Patch** /v1/appClipAdvancedExperiences/{id} | 



## AppClipAdvancedExperiencesCreateInstance

> AppClipAdvancedExperienceResponse AppClipAdvancedExperiencesCreateInstance(ctx).AppClipAdvancedExperienceCreateRequest(appClipAdvancedExperienceCreateRequest).Execute()



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
    appClipAdvancedExperienceCreateRequest := *openapiclient.NewAppClipAdvancedExperienceCreateRequest(*openapiclient.NewAppClipAdvancedExperienceCreateRequestData("Type_example", *openapiclient.NewAppClipAdvancedExperienceCreateRequestDataAttributes("Link_example", false, openapiclient.AppClipAdvancedExperienceLanguage("AR")), *openapiclient.NewAppClipAdvancedExperienceCreateRequestDataRelationships(*openapiclient.NewAppClipAdvancedExperienceCreateRequestDataRelationshipsAppClip(*openapiclient.NewAppClipAdvancedExperienceRelationshipsAppClipData("Type_example", "Id_example")), *openapiclient.NewAppClipAdvancedExperienceCreateRequestDataRelationshipsHeaderImage(*openapiclient.NewAppClipAdvancedExperienceRelationshipsHeaderImageData("Type_example", "Id_example")), *openapiclient.NewAppClipAdvancedExperienceCreateRequestDataRelationshipsLocalizations([]openapiclient.AppClipAdvancedExperienceRelationshipsLocalizationsDataInner{*openapiclient.NewAppClipAdvancedExperienceRelationshipsLocalizationsDataInner("Type_example", "Id_example")})))) // AppClipAdvancedExperienceCreateRequest | AppClipAdvancedExperience representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppClipAdvancedExperiencesApi.AppClipAdvancedExperiencesCreateInstance(context.Background()).AppClipAdvancedExperienceCreateRequest(appClipAdvancedExperienceCreateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppClipAdvancedExperiencesApi.AppClipAdvancedExperiencesCreateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppClipAdvancedExperiencesCreateInstance`: AppClipAdvancedExperienceResponse
    fmt.Fprintf(os.Stdout, "Response from `AppClipAdvancedExperiencesApi.AppClipAdvancedExperiencesCreateInstance`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiAppClipAdvancedExperiencesCreateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **appClipAdvancedExperienceCreateRequest** | [**AppClipAdvancedExperienceCreateRequest**](AppClipAdvancedExperienceCreateRequest.md) | AppClipAdvancedExperience representation | 

### Return type

[**AppClipAdvancedExperienceResponse**](AppClipAdvancedExperienceResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppClipAdvancedExperiencesGetInstance

> AppClipAdvancedExperienceResponse AppClipAdvancedExperiencesGetInstance(ctx, id).FieldsAppClipAdvancedExperiences(fieldsAppClipAdvancedExperiences).Include(include).LimitLocalizations(limitLocalizations).Execute()



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
    fieldsAppClipAdvancedExperiences := []string{"FieldsAppClipAdvancedExperiences_example"} // []string | the fields to include for returned resources of type appClipAdvancedExperiences (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)
    limitLocalizations := int32(56) // int32 | maximum number of related localizations returned (when they are included) (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppClipAdvancedExperiencesApi.AppClipAdvancedExperiencesGetInstance(context.Background(), id).FieldsAppClipAdvancedExperiences(fieldsAppClipAdvancedExperiences).Include(include).LimitLocalizations(limitLocalizations).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppClipAdvancedExperiencesApi.AppClipAdvancedExperiencesGetInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppClipAdvancedExperiencesGetInstance`: AppClipAdvancedExperienceResponse
    fmt.Fprintf(os.Stdout, "Response from `AppClipAdvancedExperiencesApi.AppClipAdvancedExperiencesGetInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppClipAdvancedExperiencesGetInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsAppClipAdvancedExperiences** | **[]string** | the fields to include for returned resources of type appClipAdvancedExperiences | 
 **include** | **[]string** | comma-separated list of relationships to include | 
 **limitLocalizations** | **int32** | maximum number of related localizations returned (when they are included) | 

### Return type

[**AppClipAdvancedExperienceResponse**](AppClipAdvancedExperienceResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppClipAdvancedExperiencesUpdateInstance

> AppClipAdvancedExperienceResponse AppClipAdvancedExperiencesUpdateInstance(ctx, id).AppClipAdvancedExperienceUpdateRequest(appClipAdvancedExperienceUpdateRequest).Execute()



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
    appClipAdvancedExperienceUpdateRequest := *openapiclient.NewAppClipAdvancedExperienceUpdateRequest(*openapiclient.NewAppClipAdvancedExperienceUpdateRequestData("Type_example", "Id_example")) // AppClipAdvancedExperienceUpdateRequest | AppClipAdvancedExperience representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppClipAdvancedExperiencesApi.AppClipAdvancedExperiencesUpdateInstance(context.Background(), id).AppClipAdvancedExperienceUpdateRequest(appClipAdvancedExperienceUpdateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppClipAdvancedExperiencesApi.AppClipAdvancedExperiencesUpdateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppClipAdvancedExperiencesUpdateInstance`: AppClipAdvancedExperienceResponse
    fmt.Fprintf(os.Stdout, "Response from `AppClipAdvancedExperiencesApi.AppClipAdvancedExperiencesUpdateInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppClipAdvancedExperiencesUpdateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **appClipAdvancedExperienceUpdateRequest** | [**AppClipAdvancedExperienceUpdateRequest**](AppClipAdvancedExperienceUpdateRequest.md) | AppClipAdvancedExperience representation | 

### Return type

[**AppClipAdvancedExperienceResponse**](AppClipAdvancedExperienceResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

