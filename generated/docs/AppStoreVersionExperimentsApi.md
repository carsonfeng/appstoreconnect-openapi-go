# \AppStoreVersionExperimentsApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**AppStoreVersionExperimentsAppStoreVersionExperimentTreatmentsGetToManyRelated**](AppStoreVersionExperimentsApi.md#AppStoreVersionExperimentsAppStoreVersionExperimentTreatmentsGetToManyRelated) | **Get** /v1/appStoreVersionExperiments/{id}/appStoreVersionExperimentTreatments | 
[**AppStoreVersionExperimentsCreateInstance**](AppStoreVersionExperimentsApi.md#AppStoreVersionExperimentsCreateInstance) | **Post** /v1/appStoreVersionExperiments | 
[**AppStoreVersionExperimentsDeleteInstance**](AppStoreVersionExperimentsApi.md#AppStoreVersionExperimentsDeleteInstance) | **Delete** /v1/appStoreVersionExperiments/{id} | 
[**AppStoreVersionExperimentsGetInstance**](AppStoreVersionExperimentsApi.md#AppStoreVersionExperimentsGetInstance) | **Get** /v1/appStoreVersionExperiments/{id} | 
[**AppStoreVersionExperimentsUpdateInstance**](AppStoreVersionExperimentsApi.md#AppStoreVersionExperimentsUpdateInstance) | **Patch** /v1/appStoreVersionExperiments/{id} | 



## AppStoreVersionExperimentsAppStoreVersionExperimentTreatmentsGetToManyRelated

> AppStoreVersionExperimentTreatmentsResponse AppStoreVersionExperimentsAppStoreVersionExperimentTreatmentsGetToManyRelated(ctx, id).FieldsAppStoreVersionExperiments(fieldsAppStoreVersionExperiments).FieldsAppStoreVersionExperimentTreatments(fieldsAppStoreVersionExperimentTreatments).FieldsAppStoreVersionExperimentTreatmentLocalizations(fieldsAppStoreVersionExperimentTreatmentLocalizations).Limit(limit).LimitAppStoreVersionExperimentTreatmentLocalizations(limitAppStoreVersionExperimentTreatmentLocalizations).Include(include).Execute()



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
    fieldsAppStoreVersionExperiments := []string{"FieldsAppStoreVersionExperiments_example"} // []string | the fields to include for returned resources of type appStoreVersionExperiments (optional)
    fieldsAppStoreVersionExperimentTreatments := []string{"FieldsAppStoreVersionExperimentTreatments_example"} // []string | the fields to include for returned resources of type appStoreVersionExperimentTreatments (optional)
    fieldsAppStoreVersionExperimentTreatmentLocalizations := []string{"FieldsAppStoreVersionExperimentTreatmentLocalizations_example"} // []string | the fields to include for returned resources of type appStoreVersionExperimentTreatmentLocalizations (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    limitAppStoreVersionExperimentTreatmentLocalizations := int32(56) // int32 | maximum number of related appStoreVersionExperimentTreatmentLocalizations returned (when they are included) (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppStoreVersionExperimentsApi.AppStoreVersionExperimentsAppStoreVersionExperimentTreatmentsGetToManyRelated(context.Background(), id).FieldsAppStoreVersionExperiments(fieldsAppStoreVersionExperiments).FieldsAppStoreVersionExperimentTreatments(fieldsAppStoreVersionExperimentTreatments).FieldsAppStoreVersionExperimentTreatmentLocalizations(fieldsAppStoreVersionExperimentTreatmentLocalizations).Limit(limit).LimitAppStoreVersionExperimentTreatmentLocalizations(limitAppStoreVersionExperimentTreatmentLocalizations).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppStoreVersionExperimentsApi.AppStoreVersionExperimentsAppStoreVersionExperimentTreatmentsGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppStoreVersionExperimentsAppStoreVersionExperimentTreatmentsGetToManyRelated`: AppStoreVersionExperimentTreatmentsResponse
    fmt.Fprintf(os.Stdout, "Response from `AppStoreVersionExperimentsApi.AppStoreVersionExperimentsAppStoreVersionExperimentTreatmentsGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppStoreVersionExperimentsAppStoreVersionExperimentTreatmentsGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsAppStoreVersionExperiments** | **[]string** | the fields to include for returned resources of type appStoreVersionExperiments | 
 **fieldsAppStoreVersionExperimentTreatments** | **[]string** | the fields to include for returned resources of type appStoreVersionExperimentTreatments | 
 **fieldsAppStoreVersionExperimentTreatmentLocalizations** | **[]string** | the fields to include for returned resources of type appStoreVersionExperimentTreatmentLocalizations | 
 **limit** | **int32** | maximum resources per page | 
 **limitAppStoreVersionExperimentTreatmentLocalizations** | **int32** | maximum number of related appStoreVersionExperimentTreatmentLocalizations returned (when they are included) | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**AppStoreVersionExperimentTreatmentsResponse**](AppStoreVersionExperimentTreatmentsResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppStoreVersionExperimentsCreateInstance

> AppStoreVersionExperimentResponse AppStoreVersionExperimentsCreateInstance(ctx).AppStoreVersionExperimentCreateRequest(appStoreVersionExperimentCreateRequest).Execute()



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
    appStoreVersionExperimentCreateRequest := *openapiclient.NewAppStoreVersionExperimentCreateRequest(*openapiclient.NewAppStoreVersionExperimentCreateRequestData("Type_example", *openapiclient.NewAppStoreVersionExperimentCreateRequestDataAttributes("Name_example", int32(123)), *openapiclient.NewAppStoreReviewDetailCreateRequestDataRelationships(*openapiclient.NewAppStoreReviewDetailCreateRequestDataRelationshipsAppStoreVersion(*openapiclient.NewAppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersionData("Type_example", "Id_example"))))) // AppStoreVersionExperimentCreateRequest | AppStoreVersionExperiment representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppStoreVersionExperimentsApi.AppStoreVersionExperimentsCreateInstance(context.Background()).AppStoreVersionExperimentCreateRequest(appStoreVersionExperimentCreateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppStoreVersionExperimentsApi.AppStoreVersionExperimentsCreateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppStoreVersionExperimentsCreateInstance`: AppStoreVersionExperimentResponse
    fmt.Fprintf(os.Stdout, "Response from `AppStoreVersionExperimentsApi.AppStoreVersionExperimentsCreateInstance`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiAppStoreVersionExperimentsCreateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **appStoreVersionExperimentCreateRequest** | [**AppStoreVersionExperimentCreateRequest**](AppStoreVersionExperimentCreateRequest.md) | AppStoreVersionExperiment representation | 

### Return type

[**AppStoreVersionExperimentResponse**](AppStoreVersionExperimentResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppStoreVersionExperimentsDeleteInstance

> AppStoreVersionExperimentsDeleteInstance(ctx, id).Execute()



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
    r, err := apiClient.AppStoreVersionExperimentsApi.AppStoreVersionExperimentsDeleteInstance(context.Background(), id).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppStoreVersionExperimentsApi.AppStoreVersionExperimentsDeleteInstance``: %v\n", err)
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

Other parameters are passed through a pointer to a apiAppStoreVersionExperimentsDeleteInstanceRequest struct via the builder pattern


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


## AppStoreVersionExperimentsGetInstance

> AppStoreVersionExperimentResponse AppStoreVersionExperimentsGetInstance(ctx, id).FieldsAppStoreVersionExperiments(fieldsAppStoreVersionExperiments).Include(include).FieldsAppStoreVersionExperimentTreatments(fieldsAppStoreVersionExperimentTreatments).LimitAppStoreVersionExperimentTreatments(limitAppStoreVersionExperimentTreatments).Execute()



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
    fieldsAppStoreVersionExperiments := []string{"FieldsAppStoreVersionExperiments_example"} // []string | the fields to include for returned resources of type appStoreVersionExperiments (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)
    fieldsAppStoreVersionExperimentTreatments := []string{"FieldsAppStoreVersionExperimentTreatments_example"} // []string | the fields to include for returned resources of type appStoreVersionExperimentTreatments (optional)
    limitAppStoreVersionExperimentTreatments := int32(56) // int32 | maximum number of related appStoreVersionExperimentTreatments returned (when they are included) (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppStoreVersionExperimentsApi.AppStoreVersionExperimentsGetInstance(context.Background(), id).FieldsAppStoreVersionExperiments(fieldsAppStoreVersionExperiments).Include(include).FieldsAppStoreVersionExperimentTreatments(fieldsAppStoreVersionExperimentTreatments).LimitAppStoreVersionExperimentTreatments(limitAppStoreVersionExperimentTreatments).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppStoreVersionExperimentsApi.AppStoreVersionExperimentsGetInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppStoreVersionExperimentsGetInstance`: AppStoreVersionExperimentResponse
    fmt.Fprintf(os.Stdout, "Response from `AppStoreVersionExperimentsApi.AppStoreVersionExperimentsGetInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppStoreVersionExperimentsGetInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsAppStoreVersionExperiments** | **[]string** | the fields to include for returned resources of type appStoreVersionExperiments | 
 **include** | **[]string** | comma-separated list of relationships to include | 
 **fieldsAppStoreVersionExperimentTreatments** | **[]string** | the fields to include for returned resources of type appStoreVersionExperimentTreatments | 
 **limitAppStoreVersionExperimentTreatments** | **int32** | maximum number of related appStoreVersionExperimentTreatments returned (when they are included) | 

### Return type

[**AppStoreVersionExperimentResponse**](AppStoreVersionExperimentResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppStoreVersionExperimentsUpdateInstance

> AppStoreVersionExperimentResponse AppStoreVersionExperimentsUpdateInstance(ctx, id).AppStoreVersionExperimentUpdateRequest(appStoreVersionExperimentUpdateRequest).Execute()



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
    appStoreVersionExperimentUpdateRequest := *openapiclient.NewAppStoreVersionExperimentUpdateRequest(*openapiclient.NewAppStoreVersionExperimentUpdateRequestData("Type_example", "Id_example")) // AppStoreVersionExperimentUpdateRequest | AppStoreVersionExperiment representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppStoreVersionExperimentsApi.AppStoreVersionExperimentsUpdateInstance(context.Background(), id).AppStoreVersionExperimentUpdateRequest(appStoreVersionExperimentUpdateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppStoreVersionExperimentsApi.AppStoreVersionExperimentsUpdateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppStoreVersionExperimentsUpdateInstance`: AppStoreVersionExperimentResponse
    fmt.Fprintf(os.Stdout, "Response from `AppStoreVersionExperimentsApi.AppStoreVersionExperimentsUpdateInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppStoreVersionExperimentsUpdateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **appStoreVersionExperimentUpdateRequest** | [**AppStoreVersionExperimentUpdateRequest**](AppStoreVersionExperimentUpdateRequest.md) | AppStoreVersionExperiment representation | 

### Return type

[**AppStoreVersionExperimentResponse**](AppStoreVersionExperimentResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

