# \AppCustomProductPageVersionsApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**AppCustomProductPageVersionsAppCustomProductPageLocalizationsGetToManyRelated**](AppCustomProductPageVersionsApi.md#AppCustomProductPageVersionsAppCustomProductPageLocalizationsGetToManyRelated) | **Get** /v1/appCustomProductPageVersions/{id}/appCustomProductPageLocalizations | 
[**AppCustomProductPageVersionsCreateInstance**](AppCustomProductPageVersionsApi.md#AppCustomProductPageVersionsCreateInstance) | **Post** /v1/appCustomProductPageVersions | 
[**AppCustomProductPageVersionsGetInstance**](AppCustomProductPageVersionsApi.md#AppCustomProductPageVersionsGetInstance) | **Get** /v1/appCustomProductPageVersions/{id} | 



## AppCustomProductPageVersionsAppCustomProductPageLocalizationsGetToManyRelated

> AppCustomProductPageLocalizationsResponse AppCustomProductPageVersionsAppCustomProductPageLocalizationsGetToManyRelated(ctx, id).FilterLocale(filterLocale).FieldsAppScreenshotSets(fieldsAppScreenshotSets).FieldsAppCustomProductPageLocalizations(fieldsAppCustomProductPageLocalizations).FieldsAppCustomProductPageVersions(fieldsAppCustomProductPageVersions).FieldsAppPreviewSets(fieldsAppPreviewSets).Limit(limit).LimitAppScreenshotSets(limitAppScreenshotSets).LimitAppPreviewSets(limitAppPreviewSets).Include(include).Execute()



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
    filterLocale := []string{"Inner_example"} // []string | filter by attribute 'locale' (optional)
    fieldsAppScreenshotSets := []string{"FieldsAppScreenshotSets_example"} // []string | the fields to include for returned resources of type appScreenshotSets (optional)
    fieldsAppCustomProductPageLocalizations := []string{"FieldsAppCustomProductPageLocalizations_example"} // []string | the fields to include for returned resources of type appCustomProductPageLocalizations (optional)
    fieldsAppCustomProductPageVersions := []string{"FieldsAppCustomProductPageVersions_example"} // []string | the fields to include for returned resources of type appCustomProductPageVersions (optional)
    fieldsAppPreviewSets := []string{"FieldsAppPreviewSets_example"} // []string | the fields to include for returned resources of type appPreviewSets (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    limitAppScreenshotSets := int32(56) // int32 | maximum number of related appScreenshotSets returned (when they are included) (optional)
    limitAppPreviewSets := int32(56) // int32 | maximum number of related appPreviewSets returned (when they are included) (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppCustomProductPageVersionsApi.AppCustomProductPageVersionsAppCustomProductPageLocalizationsGetToManyRelated(context.Background(), id).FilterLocale(filterLocale).FieldsAppScreenshotSets(fieldsAppScreenshotSets).FieldsAppCustomProductPageLocalizations(fieldsAppCustomProductPageLocalizations).FieldsAppCustomProductPageVersions(fieldsAppCustomProductPageVersions).FieldsAppPreviewSets(fieldsAppPreviewSets).Limit(limit).LimitAppScreenshotSets(limitAppScreenshotSets).LimitAppPreviewSets(limitAppPreviewSets).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppCustomProductPageVersionsApi.AppCustomProductPageVersionsAppCustomProductPageLocalizationsGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppCustomProductPageVersionsAppCustomProductPageLocalizationsGetToManyRelated`: AppCustomProductPageLocalizationsResponse
    fmt.Fprintf(os.Stdout, "Response from `AppCustomProductPageVersionsApi.AppCustomProductPageVersionsAppCustomProductPageLocalizationsGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppCustomProductPageVersionsAppCustomProductPageLocalizationsGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **filterLocale** | **[]string** | filter by attribute &#39;locale&#39; | 
 **fieldsAppScreenshotSets** | **[]string** | the fields to include for returned resources of type appScreenshotSets | 
 **fieldsAppCustomProductPageLocalizations** | **[]string** | the fields to include for returned resources of type appCustomProductPageLocalizations | 
 **fieldsAppCustomProductPageVersions** | **[]string** | the fields to include for returned resources of type appCustomProductPageVersions | 
 **fieldsAppPreviewSets** | **[]string** | the fields to include for returned resources of type appPreviewSets | 
 **limit** | **int32** | maximum resources per page | 
 **limitAppScreenshotSets** | **int32** | maximum number of related appScreenshotSets returned (when they are included) | 
 **limitAppPreviewSets** | **int32** | maximum number of related appPreviewSets returned (when they are included) | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**AppCustomProductPageLocalizationsResponse**](AppCustomProductPageLocalizationsResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppCustomProductPageVersionsCreateInstance

> AppCustomProductPageVersionResponse AppCustomProductPageVersionsCreateInstance(ctx).AppCustomProductPageVersionCreateRequest(appCustomProductPageVersionCreateRequest).Execute()



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
    appCustomProductPageVersionCreateRequest := *openapiclient.NewAppCustomProductPageVersionCreateRequest(*openapiclient.NewAppCustomProductPageVersionCreateRequestData("Type_example", *openapiclient.NewAppCustomProductPageVersionCreateRequestDataRelationships(*openapiclient.NewAppCustomProductPageVersionCreateRequestDataRelationshipsAppCustomProductPage(*openapiclient.NewAppCustomProductPageVersionRelationshipsAppCustomProductPageData("Type_example", "Id_example"))))) // AppCustomProductPageVersionCreateRequest | AppCustomProductPageVersion representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppCustomProductPageVersionsApi.AppCustomProductPageVersionsCreateInstance(context.Background()).AppCustomProductPageVersionCreateRequest(appCustomProductPageVersionCreateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppCustomProductPageVersionsApi.AppCustomProductPageVersionsCreateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppCustomProductPageVersionsCreateInstance`: AppCustomProductPageVersionResponse
    fmt.Fprintf(os.Stdout, "Response from `AppCustomProductPageVersionsApi.AppCustomProductPageVersionsCreateInstance`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiAppCustomProductPageVersionsCreateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **appCustomProductPageVersionCreateRequest** | [**AppCustomProductPageVersionCreateRequest**](AppCustomProductPageVersionCreateRequest.md) | AppCustomProductPageVersion representation | 

### Return type

[**AppCustomProductPageVersionResponse**](AppCustomProductPageVersionResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppCustomProductPageVersionsGetInstance

> AppCustomProductPageVersionResponse AppCustomProductPageVersionsGetInstance(ctx, id).FieldsAppCustomProductPageVersions(fieldsAppCustomProductPageVersions).Include(include).FieldsAppCustomProductPageLocalizations(fieldsAppCustomProductPageLocalizations).LimitAppCustomProductPageLocalizations(limitAppCustomProductPageLocalizations).Execute()



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
    fieldsAppCustomProductPageVersions := []string{"FieldsAppCustomProductPageVersions_example"} // []string | the fields to include for returned resources of type appCustomProductPageVersions (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)
    fieldsAppCustomProductPageLocalizations := []string{"FieldsAppCustomProductPageLocalizations_example"} // []string | the fields to include for returned resources of type appCustomProductPageLocalizations (optional)
    limitAppCustomProductPageLocalizations := int32(56) // int32 | maximum number of related appCustomProductPageLocalizations returned (when they are included) (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppCustomProductPageVersionsApi.AppCustomProductPageVersionsGetInstance(context.Background(), id).FieldsAppCustomProductPageVersions(fieldsAppCustomProductPageVersions).Include(include).FieldsAppCustomProductPageLocalizations(fieldsAppCustomProductPageLocalizations).LimitAppCustomProductPageLocalizations(limitAppCustomProductPageLocalizations).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppCustomProductPageVersionsApi.AppCustomProductPageVersionsGetInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppCustomProductPageVersionsGetInstance`: AppCustomProductPageVersionResponse
    fmt.Fprintf(os.Stdout, "Response from `AppCustomProductPageVersionsApi.AppCustomProductPageVersionsGetInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppCustomProductPageVersionsGetInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsAppCustomProductPageVersions** | **[]string** | the fields to include for returned resources of type appCustomProductPageVersions | 
 **include** | **[]string** | comma-separated list of relationships to include | 
 **fieldsAppCustomProductPageLocalizations** | **[]string** | the fields to include for returned resources of type appCustomProductPageLocalizations | 
 **limitAppCustomProductPageLocalizations** | **int32** | maximum number of related appCustomProductPageLocalizations returned (when they are included) | 

### Return type

[**AppCustomProductPageVersionResponse**](AppCustomProductPageVersionResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

