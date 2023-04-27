# \AppClipsApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**AppClipsAppClipAdvancedExperiencesGetToManyRelated**](AppClipsApi.md#AppClipsAppClipAdvancedExperiencesGetToManyRelated) | **Get** /v1/appClips/{id}/appClipAdvancedExperiences | 
[**AppClipsAppClipDefaultExperiencesGetToManyRelated**](AppClipsApi.md#AppClipsAppClipDefaultExperiencesGetToManyRelated) | **Get** /v1/appClips/{id}/appClipDefaultExperiences | 
[**AppClipsGetInstance**](AppClipsApi.md#AppClipsGetInstance) | **Get** /v1/appClips/{id} | 



## AppClipsAppClipAdvancedExperiencesGetToManyRelated

> AppClipAdvancedExperiencesResponse AppClipsAppClipAdvancedExperiencesGetToManyRelated(ctx, id).FilterAction(filterAction).FilterPlaceStatus(filterPlaceStatus).FilterStatus(filterStatus).FieldsAppClipAdvancedExperiences(fieldsAppClipAdvancedExperiences).FieldsAppClips(fieldsAppClips).FieldsAppClipAdvancedExperienceImages(fieldsAppClipAdvancedExperienceImages).FieldsAppClipAdvancedExperienceLocalizations(fieldsAppClipAdvancedExperienceLocalizations).Limit(limit).LimitLocalizations(limitLocalizations).Include(include).Execute()



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
    filterAction := []string{"FilterAction_example"} // []string | filter by attribute 'action' (optional)
    filterPlaceStatus := []string{"FilterPlaceStatus_example"} // []string | filter by attribute 'placeStatus' (optional)
    filterStatus := []string{"FilterStatus_example"} // []string | filter by attribute 'status' (optional)
    fieldsAppClipAdvancedExperiences := []string{"FieldsAppClipAdvancedExperiences_example"} // []string | the fields to include for returned resources of type appClipAdvancedExperiences (optional)
    fieldsAppClips := []string{"FieldsAppClips_example"} // []string | the fields to include for returned resources of type appClips (optional)
    fieldsAppClipAdvancedExperienceImages := []string{"FieldsAppClipAdvancedExperienceImages_example"} // []string | the fields to include for returned resources of type appClipAdvancedExperienceImages (optional)
    fieldsAppClipAdvancedExperienceLocalizations := []string{"FieldsAppClipAdvancedExperienceLocalizations_example"} // []string | the fields to include for returned resources of type appClipAdvancedExperienceLocalizations (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    limitLocalizations := int32(56) // int32 | maximum number of related localizations returned (when they are included) (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppClipsApi.AppClipsAppClipAdvancedExperiencesGetToManyRelated(context.Background(), id).FilterAction(filterAction).FilterPlaceStatus(filterPlaceStatus).FilterStatus(filterStatus).FieldsAppClipAdvancedExperiences(fieldsAppClipAdvancedExperiences).FieldsAppClips(fieldsAppClips).FieldsAppClipAdvancedExperienceImages(fieldsAppClipAdvancedExperienceImages).FieldsAppClipAdvancedExperienceLocalizations(fieldsAppClipAdvancedExperienceLocalizations).Limit(limit).LimitLocalizations(limitLocalizations).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppClipsApi.AppClipsAppClipAdvancedExperiencesGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppClipsAppClipAdvancedExperiencesGetToManyRelated`: AppClipAdvancedExperiencesResponse
    fmt.Fprintf(os.Stdout, "Response from `AppClipsApi.AppClipsAppClipAdvancedExperiencesGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppClipsAppClipAdvancedExperiencesGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **filterAction** | **[]string** | filter by attribute &#39;action&#39; | 
 **filterPlaceStatus** | **[]string** | filter by attribute &#39;placeStatus&#39; | 
 **filterStatus** | **[]string** | filter by attribute &#39;status&#39; | 
 **fieldsAppClipAdvancedExperiences** | **[]string** | the fields to include for returned resources of type appClipAdvancedExperiences | 
 **fieldsAppClips** | **[]string** | the fields to include for returned resources of type appClips | 
 **fieldsAppClipAdvancedExperienceImages** | **[]string** | the fields to include for returned resources of type appClipAdvancedExperienceImages | 
 **fieldsAppClipAdvancedExperienceLocalizations** | **[]string** | the fields to include for returned resources of type appClipAdvancedExperienceLocalizations | 
 **limit** | **int32** | maximum resources per page | 
 **limitLocalizations** | **int32** | maximum number of related localizations returned (when they are included) | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**AppClipAdvancedExperiencesResponse**](AppClipAdvancedExperiencesResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppClipsAppClipDefaultExperiencesGetToManyRelated

> AppClipDefaultExperiencesResponse AppClipsAppClipDefaultExperiencesGetToManyRelated(ctx, id).ExistsReleaseWithAppStoreVersion(existsReleaseWithAppStoreVersion).FieldsAppClips(fieldsAppClips).FieldsAppClipAppStoreReviewDetails(fieldsAppClipAppStoreReviewDetails).FieldsAppStoreVersions(fieldsAppStoreVersions).FieldsAppClipDefaultExperiences(fieldsAppClipDefaultExperiences).FieldsAppClipDefaultExperienceLocalizations(fieldsAppClipDefaultExperienceLocalizations).Limit(limit).LimitAppClipDefaultExperienceLocalizations(limitAppClipDefaultExperienceLocalizations).Include(include).Execute()



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
    existsReleaseWithAppStoreVersion := true // bool | filter by existence or non-existence of related 'releaseWithAppStoreVersion' (optional)
    fieldsAppClips := []string{"FieldsAppClips_example"} // []string | the fields to include for returned resources of type appClips (optional)
    fieldsAppClipAppStoreReviewDetails := []string{"FieldsAppClipAppStoreReviewDetails_example"} // []string | the fields to include for returned resources of type appClipAppStoreReviewDetails (optional)
    fieldsAppStoreVersions := []string{"FieldsAppStoreVersions_example"} // []string | the fields to include for returned resources of type appStoreVersions (optional)
    fieldsAppClipDefaultExperiences := []string{"FieldsAppClipDefaultExperiences_example"} // []string | the fields to include for returned resources of type appClipDefaultExperiences (optional)
    fieldsAppClipDefaultExperienceLocalizations := []string{"FieldsAppClipDefaultExperienceLocalizations_example"} // []string | the fields to include for returned resources of type appClipDefaultExperienceLocalizations (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    limitAppClipDefaultExperienceLocalizations := int32(56) // int32 | maximum number of related appClipDefaultExperienceLocalizations returned (when they are included) (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppClipsApi.AppClipsAppClipDefaultExperiencesGetToManyRelated(context.Background(), id).ExistsReleaseWithAppStoreVersion(existsReleaseWithAppStoreVersion).FieldsAppClips(fieldsAppClips).FieldsAppClipAppStoreReviewDetails(fieldsAppClipAppStoreReviewDetails).FieldsAppStoreVersions(fieldsAppStoreVersions).FieldsAppClipDefaultExperiences(fieldsAppClipDefaultExperiences).FieldsAppClipDefaultExperienceLocalizations(fieldsAppClipDefaultExperienceLocalizations).Limit(limit).LimitAppClipDefaultExperienceLocalizations(limitAppClipDefaultExperienceLocalizations).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppClipsApi.AppClipsAppClipDefaultExperiencesGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppClipsAppClipDefaultExperiencesGetToManyRelated`: AppClipDefaultExperiencesResponse
    fmt.Fprintf(os.Stdout, "Response from `AppClipsApi.AppClipsAppClipDefaultExperiencesGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppClipsAppClipDefaultExperiencesGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **existsReleaseWithAppStoreVersion** | **bool** | filter by existence or non-existence of related &#39;releaseWithAppStoreVersion&#39; | 
 **fieldsAppClips** | **[]string** | the fields to include for returned resources of type appClips | 
 **fieldsAppClipAppStoreReviewDetails** | **[]string** | the fields to include for returned resources of type appClipAppStoreReviewDetails | 
 **fieldsAppStoreVersions** | **[]string** | the fields to include for returned resources of type appStoreVersions | 
 **fieldsAppClipDefaultExperiences** | **[]string** | the fields to include for returned resources of type appClipDefaultExperiences | 
 **fieldsAppClipDefaultExperienceLocalizations** | **[]string** | the fields to include for returned resources of type appClipDefaultExperienceLocalizations | 
 **limit** | **int32** | maximum resources per page | 
 **limitAppClipDefaultExperienceLocalizations** | **int32** | maximum number of related appClipDefaultExperienceLocalizations returned (when they are included) | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**AppClipDefaultExperiencesResponse**](AppClipDefaultExperiencesResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppClipsGetInstance

> AppClipResponse AppClipsGetInstance(ctx, id).FieldsAppClips(fieldsAppClips).Include(include).FieldsAppClipAdvancedExperiences(fieldsAppClipAdvancedExperiences).FieldsAppClipDefaultExperiences(fieldsAppClipDefaultExperiences).LimitAppClipDefaultExperiences(limitAppClipDefaultExperiences).Execute()



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
    fieldsAppClips := []string{"FieldsAppClips_example"} // []string | the fields to include for returned resources of type appClips (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)
    fieldsAppClipAdvancedExperiences := []string{"FieldsAppClipAdvancedExperiences_example"} // []string | the fields to include for returned resources of type appClipAdvancedExperiences (optional)
    fieldsAppClipDefaultExperiences := []string{"FieldsAppClipDefaultExperiences_example"} // []string | the fields to include for returned resources of type appClipDefaultExperiences (optional)
    limitAppClipDefaultExperiences := int32(56) // int32 | maximum number of related appClipDefaultExperiences returned (when they are included) (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppClipsApi.AppClipsGetInstance(context.Background(), id).FieldsAppClips(fieldsAppClips).Include(include).FieldsAppClipAdvancedExperiences(fieldsAppClipAdvancedExperiences).FieldsAppClipDefaultExperiences(fieldsAppClipDefaultExperiences).LimitAppClipDefaultExperiences(limitAppClipDefaultExperiences).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppClipsApi.AppClipsGetInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppClipsGetInstance`: AppClipResponse
    fmt.Fprintf(os.Stdout, "Response from `AppClipsApi.AppClipsGetInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppClipsGetInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsAppClips** | **[]string** | the fields to include for returned resources of type appClips | 
 **include** | **[]string** | comma-separated list of relationships to include | 
 **fieldsAppClipAdvancedExperiences** | **[]string** | the fields to include for returned resources of type appClipAdvancedExperiences | 
 **fieldsAppClipDefaultExperiences** | **[]string** | the fields to include for returned resources of type appClipDefaultExperiences | 
 **limitAppClipDefaultExperiences** | **int32** | maximum number of related appClipDefaultExperiences returned (when they are included) | 

### Return type

[**AppClipResponse**](AppClipResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

