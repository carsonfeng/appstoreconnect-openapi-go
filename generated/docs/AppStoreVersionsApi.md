# \AppStoreVersionsApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**AppStoreVersionsAgeRatingDeclarationGetToOneRelated**](AppStoreVersionsApi.md#AppStoreVersionsAgeRatingDeclarationGetToOneRelated) | **Get** /v1/appStoreVersions/{id}/ageRatingDeclaration | 
[**AppStoreVersionsAppClipDefaultExperienceGetToOneRelated**](AppStoreVersionsApi.md#AppStoreVersionsAppClipDefaultExperienceGetToOneRelated) | **Get** /v1/appStoreVersions/{id}/appClipDefaultExperience | 
[**AppStoreVersionsAppClipDefaultExperienceGetToOneRelationship**](AppStoreVersionsApi.md#AppStoreVersionsAppClipDefaultExperienceGetToOneRelationship) | **Get** /v1/appStoreVersions/{id}/relationships/appClipDefaultExperience | 
[**AppStoreVersionsAppClipDefaultExperienceUpdateToOneRelationship**](AppStoreVersionsApi.md#AppStoreVersionsAppClipDefaultExperienceUpdateToOneRelationship) | **Patch** /v1/appStoreVersions/{id}/relationships/appClipDefaultExperience | 
[**AppStoreVersionsAppStoreReviewDetailGetToOneRelated**](AppStoreVersionsApi.md#AppStoreVersionsAppStoreReviewDetailGetToOneRelated) | **Get** /v1/appStoreVersions/{id}/appStoreReviewDetail | 
[**AppStoreVersionsAppStoreVersionExperimentsGetToManyRelated**](AppStoreVersionsApi.md#AppStoreVersionsAppStoreVersionExperimentsGetToManyRelated) | **Get** /v1/appStoreVersions/{id}/appStoreVersionExperiments | 
[**AppStoreVersionsAppStoreVersionLocalizationsGetToManyRelated**](AppStoreVersionsApi.md#AppStoreVersionsAppStoreVersionLocalizationsGetToManyRelated) | **Get** /v1/appStoreVersions/{id}/appStoreVersionLocalizations | 
[**AppStoreVersionsAppStoreVersionPhasedReleaseGetToOneRelated**](AppStoreVersionsApi.md#AppStoreVersionsAppStoreVersionPhasedReleaseGetToOneRelated) | **Get** /v1/appStoreVersions/{id}/appStoreVersionPhasedRelease | 
[**AppStoreVersionsAppStoreVersionSubmissionGetToOneRelated**](AppStoreVersionsApi.md#AppStoreVersionsAppStoreVersionSubmissionGetToOneRelated) | **Get** /v1/appStoreVersions/{id}/appStoreVersionSubmission | 
[**AppStoreVersionsBuildGetToOneRelated**](AppStoreVersionsApi.md#AppStoreVersionsBuildGetToOneRelated) | **Get** /v1/appStoreVersions/{id}/build | 
[**AppStoreVersionsBuildGetToOneRelationship**](AppStoreVersionsApi.md#AppStoreVersionsBuildGetToOneRelationship) | **Get** /v1/appStoreVersions/{id}/relationships/build | 
[**AppStoreVersionsBuildUpdateToOneRelationship**](AppStoreVersionsApi.md#AppStoreVersionsBuildUpdateToOneRelationship) | **Patch** /v1/appStoreVersions/{id}/relationships/build | 
[**AppStoreVersionsCreateInstance**](AppStoreVersionsApi.md#AppStoreVersionsCreateInstance) | **Post** /v1/appStoreVersions | 
[**AppStoreVersionsCustomerReviewsGetToManyRelated**](AppStoreVersionsApi.md#AppStoreVersionsCustomerReviewsGetToManyRelated) | **Get** /v1/appStoreVersions/{id}/customerReviews | 
[**AppStoreVersionsDeleteInstance**](AppStoreVersionsApi.md#AppStoreVersionsDeleteInstance) | **Delete** /v1/appStoreVersions/{id} | 
[**AppStoreVersionsGetInstance**](AppStoreVersionsApi.md#AppStoreVersionsGetInstance) | **Get** /v1/appStoreVersions/{id} | 
[**AppStoreVersionsRoutingAppCoverageGetToOneRelated**](AppStoreVersionsApi.md#AppStoreVersionsRoutingAppCoverageGetToOneRelated) | **Get** /v1/appStoreVersions/{id}/routingAppCoverage | 
[**AppStoreVersionsUpdateInstance**](AppStoreVersionsApi.md#AppStoreVersionsUpdateInstance) | **Patch** /v1/appStoreVersions/{id} | 



## AppStoreVersionsAgeRatingDeclarationGetToOneRelated

> AgeRatingDeclarationResponse AppStoreVersionsAgeRatingDeclarationGetToOneRelated(ctx, id).FieldsAgeRatingDeclarations(fieldsAgeRatingDeclarations).Execute()



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
    fieldsAgeRatingDeclarations := []string{"FieldsAgeRatingDeclarations_example"} // []string | the fields to include for returned resources of type ageRatingDeclarations (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppStoreVersionsApi.AppStoreVersionsAgeRatingDeclarationGetToOneRelated(context.Background(), id).FieldsAgeRatingDeclarations(fieldsAgeRatingDeclarations).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppStoreVersionsApi.AppStoreVersionsAgeRatingDeclarationGetToOneRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppStoreVersionsAgeRatingDeclarationGetToOneRelated`: AgeRatingDeclarationResponse
    fmt.Fprintf(os.Stdout, "Response from `AppStoreVersionsApi.AppStoreVersionsAgeRatingDeclarationGetToOneRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppStoreVersionsAgeRatingDeclarationGetToOneRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsAgeRatingDeclarations** | **[]string** | the fields to include for returned resources of type ageRatingDeclarations | 

### Return type

[**AgeRatingDeclarationResponse**](AgeRatingDeclarationResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppStoreVersionsAppClipDefaultExperienceGetToOneRelated

> AppClipDefaultExperienceResponse AppStoreVersionsAppClipDefaultExperienceGetToOneRelated(ctx, id).FieldsAppClips(fieldsAppClips).FieldsAppClipAppStoreReviewDetails(fieldsAppClipAppStoreReviewDetails).FieldsAppStoreVersions(fieldsAppStoreVersions).FieldsAppClipDefaultExperiences(fieldsAppClipDefaultExperiences).FieldsAppClipDefaultExperienceLocalizations(fieldsAppClipDefaultExperienceLocalizations).LimitAppClipDefaultExperienceLocalizations(limitAppClipDefaultExperienceLocalizations).Include(include).Execute()



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
    fieldsAppClipAppStoreReviewDetails := []string{"FieldsAppClipAppStoreReviewDetails_example"} // []string | the fields to include for returned resources of type appClipAppStoreReviewDetails (optional)
    fieldsAppStoreVersions := []string{"FieldsAppStoreVersions_example"} // []string | the fields to include for returned resources of type appStoreVersions (optional)
    fieldsAppClipDefaultExperiences := []string{"FieldsAppClipDefaultExperiences_example"} // []string | the fields to include for returned resources of type appClipDefaultExperiences (optional)
    fieldsAppClipDefaultExperienceLocalizations := []string{"FieldsAppClipDefaultExperienceLocalizations_example"} // []string | the fields to include for returned resources of type appClipDefaultExperienceLocalizations (optional)
    limitAppClipDefaultExperienceLocalizations := int32(56) // int32 | maximum number of related appClipDefaultExperienceLocalizations returned (when they are included) (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppStoreVersionsApi.AppStoreVersionsAppClipDefaultExperienceGetToOneRelated(context.Background(), id).FieldsAppClips(fieldsAppClips).FieldsAppClipAppStoreReviewDetails(fieldsAppClipAppStoreReviewDetails).FieldsAppStoreVersions(fieldsAppStoreVersions).FieldsAppClipDefaultExperiences(fieldsAppClipDefaultExperiences).FieldsAppClipDefaultExperienceLocalizations(fieldsAppClipDefaultExperienceLocalizations).LimitAppClipDefaultExperienceLocalizations(limitAppClipDefaultExperienceLocalizations).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppStoreVersionsApi.AppStoreVersionsAppClipDefaultExperienceGetToOneRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppStoreVersionsAppClipDefaultExperienceGetToOneRelated`: AppClipDefaultExperienceResponse
    fmt.Fprintf(os.Stdout, "Response from `AppStoreVersionsApi.AppStoreVersionsAppClipDefaultExperienceGetToOneRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppStoreVersionsAppClipDefaultExperienceGetToOneRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsAppClips** | **[]string** | the fields to include for returned resources of type appClips | 
 **fieldsAppClipAppStoreReviewDetails** | **[]string** | the fields to include for returned resources of type appClipAppStoreReviewDetails | 
 **fieldsAppStoreVersions** | **[]string** | the fields to include for returned resources of type appStoreVersions | 
 **fieldsAppClipDefaultExperiences** | **[]string** | the fields to include for returned resources of type appClipDefaultExperiences | 
 **fieldsAppClipDefaultExperienceLocalizations** | **[]string** | the fields to include for returned resources of type appClipDefaultExperienceLocalizations | 
 **limitAppClipDefaultExperienceLocalizations** | **int32** | maximum number of related appClipDefaultExperienceLocalizations returned (when they are included) | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**AppClipDefaultExperienceResponse**](AppClipDefaultExperienceResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppStoreVersionsAppClipDefaultExperienceGetToOneRelationship

> AppStoreVersionAppClipDefaultExperienceLinkageResponse AppStoreVersionsAppClipDefaultExperienceGetToOneRelationship(ctx, id).Execute()



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
    resp, r, err := apiClient.AppStoreVersionsApi.AppStoreVersionsAppClipDefaultExperienceGetToOneRelationship(context.Background(), id).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppStoreVersionsApi.AppStoreVersionsAppClipDefaultExperienceGetToOneRelationship``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppStoreVersionsAppClipDefaultExperienceGetToOneRelationship`: AppStoreVersionAppClipDefaultExperienceLinkageResponse
    fmt.Fprintf(os.Stdout, "Response from `AppStoreVersionsApi.AppStoreVersionsAppClipDefaultExperienceGetToOneRelationship`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppStoreVersionsAppClipDefaultExperienceGetToOneRelationshipRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------


### Return type

[**AppStoreVersionAppClipDefaultExperienceLinkageResponse**](AppStoreVersionAppClipDefaultExperienceLinkageResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppStoreVersionsAppClipDefaultExperienceUpdateToOneRelationship

> AppStoreVersionsAppClipDefaultExperienceUpdateToOneRelationship(ctx, id).AppStoreVersionAppClipDefaultExperienceLinkageRequest(appStoreVersionAppClipDefaultExperienceLinkageRequest).Execute()



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
    appStoreVersionAppClipDefaultExperienceLinkageRequest := *openapiclient.NewAppStoreVersionAppClipDefaultExperienceLinkageRequest(*openapiclient.NewAppClipAppStoreReviewDetailRelationshipsAppClipDefaultExperienceData("Type_example", "Id_example")) // AppStoreVersionAppClipDefaultExperienceLinkageRequest | Related linkage

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    r, err := apiClient.AppStoreVersionsApi.AppStoreVersionsAppClipDefaultExperienceUpdateToOneRelationship(context.Background(), id).AppStoreVersionAppClipDefaultExperienceLinkageRequest(appStoreVersionAppClipDefaultExperienceLinkageRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppStoreVersionsApi.AppStoreVersionsAppClipDefaultExperienceUpdateToOneRelationship``: %v\n", err)
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

Other parameters are passed through a pointer to a apiAppStoreVersionsAppClipDefaultExperienceUpdateToOneRelationshipRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **appStoreVersionAppClipDefaultExperienceLinkageRequest** | [**AppStoreVersionAppClipDefaultExperienceLinkageRequest**](AppStoreVersionAppClipDefaultExperienceLinkageRequest.md) | Related linkage | 

### Return type

 (empty response body)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppStoreVersionsAppStoreReviewDetailGetToOneRelated

> AppStoreReviewDetailResponse AppStoreVersionsAppStoreReviewDetailGetToOneRelated(ctx, id).FieldsAppStoreReviewDetails(fieldsAppStoreReviewDetails).FieldsAppStoreVersions(fieldsAppStoreVersions).FieldsAppStoreReviewAttachments(fieldsAppStoreReviewAttachments).LimitAppStoreReviewAttachments(limitAppStoreReviewAttachments).Include(include).Execute()



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
    fieldsAppStoreReviewDetails := []string{"FieldsAppStoreReviewDetails_example"} // []string | the fields to include for returned resources of type appStoreReviewDetails (optional)
    fieldsAppStoreVersions := []string{"FieldsAppStoreVersions_example"} // []string | the fields to include for returned resources of type appStoreVersions (optional)
    fieldsAppStoreReviewAttachments := []string{"FieldsAppStoreReviewAttachments_example"} // []string | the fields to include for returned resources of type appStoreReviewAttachments (optional)
    limitAppStoreReviewAttachments := int32(56) // int32 | maximum number of related appStoreReviewAttachments returned (when they are included) (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppStoreVersionsApi.AppStoreVersionsAppStoreReviewDetailGetToOneRelated(context.Background(), id).FieldsAppStoreReviewDetails(fieldsAppStoreReviewDetails).FieldsAppStoreVersions(fieldsAppStoreVersions).FieldsAppStoreReviewAttachments(fieldsAppStoreReviewAttachments).LimitAppStoreReviewAttachments(limitAppStoreReviewAttachments).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppStoreVersionsApi.AppStoreVersionsAppStoreReviewDetailGetToOneRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppStoreVersionsAppStoreReviewDetailGetToOneRelated`: AppStoreReviewDetailResponse
    fmt.Fprintf(os.Stdout, "Response from `AppStoreVersionsApi.AppStoreVersionsAppStoreReviewDetailGetToOneRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppStoreVersionsAppStoreReviewDetailGetToOneRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsAppStoreReviewDetails** | **[]string** | the fields to include for returned resources of type appStoreReviewDetails | 
 **fieldsAppStoreVersions** | **[]string** | the fields to include for returned resources of type appStoreVersions | 
 **fieldsAppStoreReviewAttachments** | **[]string** | the fields to include for returned resources of type appStoreReviewAttachments | 
 **limitAppStoreReviewAttachments** | **int32** | maximum number of related appStoreReviewAttachments returned (when they are included) | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**AppStoreReviewDetailResponse**](AppStoreReviewDetailResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppStoreVersionsAppStoreVersionExperimentsGetToManyRelated

> AppStoreVersionExperimentsResponse AppStoreVersionsAppStoreVersionExperimentsGetToManyRelated(ctx, id).FilterState(filterState).FieldsAppStoreVersionExperiments(fieldsAppStoreVersionExperiments).FieldsAppStoreVersionExperimentTreatments(fieldsAppStoreVersionExperimentTreatments).FieldsAppStoreVersions(fieldsAppStoreVersions).Limit(limit).LimitAppStoreVersionExperimentTreatments(limitAppStoreVersionExperimentTreatments).Include(include).Execute()



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
    filterState := []string{"FilterState_example"} // []string | filter by attribute 'state' (optional)
    fieldsAppStoreVersionExperiments := []string{"FieldsAppStoreVersionExperiments_example"} // []string | the fields to include for returned resources of type appStoreVersionExperiments (optional)
    fieldsAppStoreVersionExperimentTreatments := []string{"FieldsAppStoreVersionExperimentTreatments_example"} // []string | the fields to include for returned resources of type appStoreVersionExperimentTreatments (optional)
    fieldsAppStoreVersions := []string{"FieldsAppStoreVersions_example"} // []string | the fields to include for returned resources of type appStoreVersions (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    limitAppStoreVersionExperimentTreatments := int32(56) // int32 | maximum number of related appStoreVersionExperimentTreatments returned (when they are included) (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppStoreVersionsApi.AppStoreVersionsAppStoreVersionExperimentsGetToManyRelated(context.Background(), id).FilterState(filterState).FieldsAppStoreVersionExperiments(fieldsAppStoreVersionExperiments).FieldsAppStoreVersionExperimentTreatments(fieldsAppStoreVersionExperimentTreatments).FieldsAppStoreVersions(fieldsAppStoreVersions).Limit(limit).LimitAppStoreVersionExperimentTreatments(limitAppStoreVersionExperimentTreatments).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppStoreVersionsApi.AppStoreVersionsAppStoreVersionExperimentsGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppStoreVersionsAppStoreVersionExperimentsGetToManyRelated`: AppStoreVersionExperimentsResponse
    fmt.Fprintf(os.Stdout, "Response from `AppStoreVersionsApi.AppStoreVersionsAppStoreVersionExperimentsGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppStoreVersionsAppStoreVersionExperimentsGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **filterState** | **[]string** | filter by attribute &#39;state&#39; | 
 **fieldsAppStoreVersionExperiments** | **[]string** | the fields to include for returned resources of type appStoreVersionExperiments | 
 **fieldsAppStoreVersionExperimentTreatments** | **[]string** | the fields to include for returned resources of type appStoreVersionExperimentTreatments | 
 **fieldsAppStoreVersions** | **[]string** | the fields to include for returned resources of type appStoreVersions | 
 **limit** | **int32** | maximum resources per page | 
 **limitAppStoreVersionExperimentTreatments** | **int32** | maximum number of related appStoreVersionExperimentTreatments returned (when they are included) | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**AppStoreVersionExperimentsResponse**](AppStoreVersionExperimentsResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppStoreVersionsAppStoreVersionLocalizationsGetToManyRelated

> AppStoreVersionLocalizationsResponse AppStoreVersionsAppStoreVersionLocalizationsGetToManyRelated(ctx, id).FieldsAppStoreVersionLocalizations(fieldsAppStoreVersionLocalizations).Limit(limit).Execute()



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
    fieldsAppStoreVersionLocalizations := []string{"FieldsAppStoreVersionLocalizations_example"} // []string | the fields to include for returned resources of type appStoreVersionLocalizations (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppStoreVersionsApi.AppStoreVersionsAppStoreVersionLocalizationsGetToManyRelated(context.Background(), id).FieldsAppStoreVersionLocalizations(fieldsAppStoreVersionLocalizations).Limit(limit).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppStoreVersionsApi.AppStoreVersionsAppStoreVersionLocalizationsGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppStoreVersionsAppStoreVersionLocalizationsGetToManyRelated`: AppStoreVersionLocalizationsResponse
    fmt.Fprintf(os.Stdout, "Response from `AppStoreVersionsApi.AppStoreVersionsAppStoreVersionLocalizationsGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppStoreVersionsAppStoreVersionLocalizationsGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsAppStoreVersionLocalizations** | **[]string** | the fields to include for returned resources of type appStoreVersionLocalizations | 
 **limit** | **int32** | maximum resources per page | 

### Return type

[**AppStoreVersionLocalizationsResponse**](AppStoreVersionLocalizationsResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppStoreVersionsAppStoreVersionPhasedReleaseGetToOneRelated

> AppStoreVersionPhasedReleaseResponse AppStoreVersionsAppStoreVersionPhasedReleaseGetToOneRelated(ctx, id).FieldsAppStoreVersionPhasedReleases(fieldsAppStoreVersionPhasedReleases).Execute()



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
    fieldsAppStoreVersionPhasedReleases := []string{"FieldsAppStoreVersionPhasedReleases_example"} // []string | the fields to include for returned resources of type appStoreVersionPhasedReleases (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppStoreVersionsApi.AppStoreVersionsAppStoreVersionPhasedReleaseGetToOneRelated(context.Background(), id).FieldsAppStoreVersionPhasedReleases(fieldsAppStoreVersionPhasedReleases).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppStoreVersionsApi.AppStoreVersionsAppStoreVersionPhasedReleaseGetToOneRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppStoreVersionsAppStoreVersionPhasedReleaseGetToOneRelated`: AppStoreVersionPhasedReleaseResponse
    fmt.Fprintf(os.Stdout, "Response from `AppStoreVersionsApi.AppStoreVersionsAppStoreVersionPhasedReleaseGetToOneRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppStoreVersionsAppStoreVersionPhasedReleaseGetToOneRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsAppStoreVersionPhasedReleases** | **[]string** | the fields to include for returned resources of type appStoreVersionPhasedReleases | 

### Return type

[**AppStoreVersionPhasedReleaseResponse**](AppStoreVersionPhasedReleaseResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppStoreVersionsAppStoreVersionSubmissionGetToOneRelated

> AppStoreVersionSubmissionResponse AppStoreVersionsAppStoreVersionSubmissionGetToOneRelated(ctx, id).FieldsAppStoreVersionSubmissions(fieldsAppStoreVersionSubmissions).FieldsAppStoreVersions(fieldsAppStoreVersions).Include(include).Execute()



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
    fieldsAppStoreVersionSubmissions := []string{"FieldsAppStoreVersionSubmissions_example"} // []string | the fields to include for returned resources of type appStoreVersionSubmissions (optional)
    fieldsAppStoreVersions := []string{"FieldsAppStoreVersions_example"} // []string | the fields to include for returned resources of type appStoreVersions (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppStoreVersionsApi.AppStoreVersionsAppStoreVersionSubmissionGetToOneRelated(context.Background(), id).FieldsAppStoreVersionSubmissions(fieldsAppStoreVersionSubmissions).FieldsAppStoreVersions(fieldsAppStoreVersions).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppStoreVersionsApi.AppStoreVersionsAppStoreVersionSubmissionGetToOneRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppStoreVersionsAppStoreVersionSubmissionGetToOneRelated`: AppStoreVersionSubmissionResponse
    fmt.Fprintf(os.Stdout, "Response from `AppStoreVersionsApi.AppStoreVersionsAppStoreVersionSubmissionGetToOneRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppStoreVersionsAppStoreVersionSubmissionGetToOneRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsAppStoreVersionSubmissions** | **[]string** | the fields to include for returned resources of type appStoreVersionSubmissions | 
 **fieldsAppStoreVersions** | **[]string** | the fields to include for returned resources of type appStoreVersions | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**AppStoreVersionSubmissionResponse**](AppStoreVersionSubmissionResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppStoreVersionsBuildGetToOneRelated

> BuildResponse AppStoreVersionsBuildGetToOneRelated(ctx, id).FieldsBuilds(fieldsBuilds).Execute()



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
    fieldsBuilds := []string{"FieldsBuilds_example"} // []string | the fields to include for returned resources of type builds (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppStoreVersionsApi.AppStoreVersionsBuildGetToOneRelated(context.Background(), id).FieldsBuilds(fieldsBuilds).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppStoreVersionsApi.AppStoreVersionsBuildGetToOneRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppStoreVersionsBuildGetToOneRelated`: BuildResponse
    fmt.Fprintf(os.Stdout, "Response from `AppStoreVersionsApi.AppStoreVersionsBuildGetToOneRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppStoreVersionsBuildGetToOneRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsBuilds** | **[]string** | the fields to include for returned resources of type builds | 

### Return type

[**BuildResponse**](BuildResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppStoreVersionsBuildGetToOneRelationship

> AppStoreVersionBuildLinkageResponse AppStoreVersionsBuildGetToOneRelationship(ctx, id).Execute()



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
    resp, r, err := apiClient.AppStoreVersionsApi.AppStoreVersionsBuildGetToOneRelationship(context.Background(), id).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppStoreVersionsApi.AppStoreVersionsBuildGetToOneRelationship``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppStoreVersionsBuildGetToOneRelationship`: AppStoreVersionBuildLinkageResponse
    fmt.Fprintf(os.Stdout, "Response from `AppStoreVersionsApi.AppStoreVersionsBuildGetToOneRelationship`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppStoreVersionsBuildGetToOneRelationshipRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------


### Return type

[**AppStoreVersionBuildLinkageResponse**](AppStoreVersionBuildLinkageResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppStoreVersionsBuildUpdateToOneRelationship

> AppStoreVersionsBuildUpdateToOneRelationship(ctx, id).AppStoreVersionBuildLinkageRequest(appStoreVersionBuildLinkageRequest).Execute()



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
    appStoreVersionBuildLinkageRequest := *openapiclient.NewAppStoreVersionBuildLinkageRequest(*openapiclient.NewAppEncryptionDeclarationRelationshipsBuildsDataInner("Type_example", "Id_example")) // AppStoreVersionBuildLinkageRequest | Related linkage

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    r, err := apiClient.AppStoreVersionsApi.AppStoreVersionsBuildUpdateToOneRelationship(context.Background(), id).AppStoreVersionBuildLinkageRequest(appStoreVersionBuildLinkageRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppStoreVersionsApi.AppStoreVersionsBuildUpdateToOneRelationship``: %v\n", err)
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

Other parameters are passed through a pointer to a apiAppStoreVersionsBuildUpdateToOneRelationshipRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **appStoreVersionBuildLinkageRequest** | [**AppStoreVersionBuildLinkageRequest**](AppStoreVersionBuildLinkageRequest.md) | Related linkage | 

### Return type

 (empty response body)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppStoreVersionsCreateInstance

> AppStoreVersionResponse AppStoreVersionsCreateInstance(ctx).AppStoreVersionCreateRequest(appStoreVersionCreateRequest).Execute()



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
    appStoreVersionCreateRequest := *openapiclient.NewAppStoreVersionCreateRequest(*openapiclient.NewAppStoreVersionCreateRequestData("Type_example", *openapiclient.NewAppStoreVersionCreateRequestDataAttributes(openapiclient.Platform("IOS"), "VersionString_example"), *openapiclient.NewAppStoreVersionCreateRequestDataRelationships(*openapiclient.NewAppAvailabilityCreateRequestDataRelationshipsApp(*openapiclient.NewAppAvailabilityRelationshipsAppData("Type_example", "Id_example"))))) // AppStoreVersionCreateRequest | AppStoreVersion representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppStoreVersionsApi.AppStoreVersionsCreateInstance(context.Background()).AppStoreVersionCreateRequest(appStoreVersionCreateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppStoreVersionsApi.AppStoreVersionsCreateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppStoreVersionsCreateInstance`: AppStoreVersionResponse
    fmt.Fprintf(os.Stdout, "Response from `AppStoreVersionsApi.AppStoreVersionsCreateInstance`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiAppStoreVersionsCreateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **appStoreVersionCreateRequest** | [**AppStoreVersionCreateRequest**](AppStoreVersionCreateRequest.md) | AppStoreVersion representation | 

### Return type

[**AppStoreVersionResponse**](AppStoreVersionResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppStoreVersionsCustomerReviewsGetToManyRelated

> CustomerReviewsResponse AppStoreVersionsCustomerReviewsGetToManyRelated(ctx, id).FilterRating(filterRating).FilterTerritory(filterTerritory).ExistsPublishedResponse(existsPublishedResponse).Sort(sort).FieldsCustomerReviews(fieldsCustomerReviews).FieldsCustomerReviewResponses(fieldsCustomerReviewResponses).Limit(limit).Include(include).Execute()



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
    filterRating := []string{"Inner_example"} // []string | filter by attribute 'rating' (optional)
    filterTerritory := []string{"FilterTerritory_example"} // []string | filter by attribute 'territory' (optional)
    existsPublishedResponse := true // bool | filter by publishedResponse (optional)
    sort := []string{"Sort_example"} // []string | comma-separated list of sort expressions; resources will be sorted as specified (optional)
    fieldsCustomerReviews := []string{"FieldsCustomerReviews_example"} // []string | the fields to include for returned resources of type customerReviews (optional)
    fieldsCustomerReviewResponses := []string{"FieldsCustomerReviewResponses_example"} // []string | the fields to include for returned resources of type customerReviewResponses (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppStoreVersionsApi.AppStoreVersionsCustomerReviewsGetToManyRelated(context.Background(), id).FilterRating(filterRating).FilterTerritory(filterTerritory).ExistsPublishedResponse(existsPublishedResponse).Sort(sort).FieldsCustomerReviews(fieldsCustomerReviews).FieldsCustomerReviewResponses(fieldsCustomerReviewResponses).Limit(limit).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppStoreVersionsApi.AppStoreVersionsCustomerReviewsGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppStoreVersionsCustomerReviewsGetToManyRelated`: CustomerReviewsResponse
    fmt.Fprintf(os.Stdout, "Response from `AppStoreVersionsApi.AppStoreVersionsCustomerReviewsGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppStoreVersionsCustomerReviewsGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **filterRating** | **[]string** | filter by attribute &#39;rating&#39; | 
 **filterTerritory** | **[]string** | filter by attribute &#39;territory&#39; | 
 **existsPublishedResponse** | **bool** | filter by publishedResponse | 
 **sort** | **[]string** | comma-separated list of sort expressions; resources will be sorted as specified | 
 **fieldsCustomerReviews** | **[]string** | the fields to include for returned resources of type customerReviews | 
 **fieldsCustomerReviewResponses** | **[]string** | the fields to include for returned resources of type customerReviewResponses | 
 **limit** | **int32** | maximum resources per page | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**CustomerReviewsResponse**](CustomerReviewsResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppStoreVersionsDeleteInstance

> AppStoreVersionsDeleteInstance(ctx, id).Execute()



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
    r, err := apiClient.AppStoreVersionsApi.AppStoreVersionsDeleteInstance(context.Background(), id).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppStoreVersionsApi.AppStoreVersionsDeleteInstance``: %v\n", err)
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

Other parameters are passed through a pointer to a apiAppStoreVersionsDeleteInstanceRequest struct via the builder pattern


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


## AppStoreVersionsGetInstance

> AppStoreVersionResponse AppStoreVersionsGetInstance(ctx, id).FieldsAppStoreVersions(fieldsAppStoreVersions).Include(include).FieldsAppStoreVersionExperiments(fieldsAppStoreVersionExperiments).FieldsAppStoreVersionSubmissions(fieldsAppStoreVersionSubmissions).FieldsAgeRatingDeclarations(fieldsAgeRatingDeclarations).FieldsCustomerReviews(fieldsCustomerReviews).FieldsAppStoreReviewDetails(fieldsAppStoreReviewDetails).FieldsAppClipDefaultExperiences(fieldsAppClipDefaultExperiences).FieldsRoutingAppCoverages(fieldsRoutingAppCoverages).FieldsAppStoreVersionPhasedReleases(fieldsAppStoreVersionPhasedReleases).FieldsBuilds(fieldsBuilds).FieldsAppStoreVersionLocalizations(fieldsAppStoreVersionLocalizations).LimitAppStoreVersionExperiments(limitAppStoreVersionExperiments).LimitAppStoreVersionLocalizations(limitAppStoreVersionLocalizations).Execute()



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
    fieldsAppStoreVersions := []string{"FieldsAppStoreVersions_example"} // []string | the fields to include for returned resources of type appStoreVersions (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)
    fieldsAppStoreVersionExperiments := []string{"FieldsAppStoreVersionExperiments_example"} // []string | the fields to include for returned resources of type appStoreVersionExperiments (optional)
    fieldsAppStoreVersionSubmissions := []string{"FieldsAppStoreVersionSubmissions_example"} // []string | the fields to include for returned resources of type appStoreVersionSubmissions (optional)
    fieldsAgeRatingDeclarations := []string{"FieldsAgeRatingDeclarations_example"} // []string | the fields to include for returned resources of type ageRatingDeclarations (optional)
    fieldsCustomerReviews := []string{"FieldsCustomerReviews_example"} // []string | the fields to include for returned resources of type customerReviews (optional)
    fieldsAppStoreReviewDetails := []string{"FieldsAppStoreReviewDetails_example"} // []string | the fields to include for returned resources of type appStoreReviewDetails (optional)
    fieldsAppClipDefaultExperiences := []string{"FieldsAppClipDefaultExperiences_example"} // []string | the fields to include for returned resources of type appClipDefaultExperiences (optional)
    fieldsRoutingAppCoverages := []string{"FieldsRoutingAppCoverages_example"} // []string | the fields to include for returned resources of type routingAppCoverages (optional)
    fieldsAppStoreVersionPhasedReleases := []string{"FieldsAppStoreVersionPhasedReleases_example"} // []string | the fields to include for returned resources of type appStoreVersionPhasedReleases (optional)
    fieldsBuilds := []string{"FieldsBuilds_example"} // []string | the fields to include for returned resources of type builds (optional)
    fieldsAppStoreVersionLocalizations := []string{"FieldsAppStoreVersionLocalizations_example"} // []string | the fields to include for returned resources of type appStoreVersionLocalizations (optional)
    limitAppStoreVersionExperiments := int32(56) // int32 | maximum number of related appStoreVersionExperiments returned (when they are included) (optional)
    limitAppStoreVersionLocalizations := int32(56) // int32 | maximum number of related appStoreVersionLocalizations returned (when they are included) (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppStoreVersionsApi.AppStoreVersionsGetInstance(context.Background(), id).FieldsAppStoreVersions(fieldsAppStoreVersions).Include(include).FieldsAppStoreVersionExperiments(fieldsAppStoreVersionExperiments).FieldsAppStoreVersionSubmissions(fieldsAppStoreVersionSubmissions).FieldsAgeRatingDeclarations(fieldsAgeRatingDeclarations).FieldsCustomerReviews(fieldsCustomerReviews).FieldsAppStoreReviewDetails(fieldsAppStoreReviewDetails).FieldsAppClipDefaultExperiences(fieldsAppClipDefaultExperiences).FieldsRoutingAppCoverages(fieldsRoutingAppCoverages).FieldsAppStoreVersionPhasedReleases(fieldsAppStoreVersionPhasedReleases).FieldsBuilds(fieldsBuilds).FieldsAppStoreVersionLocalizations(fieldsAppStoreVersionLocalizations).LimitAppStoreVersionExperiments(limitAppStoreVersionExperiments).LimitAppStoreVersionLocalizations(limitAppStoreVersionLocalizations).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppStoreVersionsApi.AppStoreVersionsGetInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppStoreVersionsGetInstance`: AppStoreVersionResponse
    fmt.Fprintf(os.Stdout, "Response from `AppStoreVersionsApi.AppStoreVersionsGetInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppStoreVersionsGetInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsAppStoreVersions** | **[]string** | the fields to include for returned resources of type appStoreVersions | 
 **include** | **[]string** | comma-separated list of relationships to include | 
 **fieldsAppStoreVersionExperiments** | **[]string** | the fields to include for returned resources of type appStoreVersionExperiments | 
 **fieldsAppStoreVersionSubmissions** | **[]string** | the fields to include for returned resources of type appStoreVersionSubmissions | 
 **fieldsAgeRatingDeclarations** | **[]string** | the fields to include for returned resources of type ageRatingDeclarations | 
 **fieldsCustomerReviews** | **[]string** | the fields to include for returned resources of type customerReviews | 
 **fieldsAppStoreReviewDetails** | **[]string** | the fields to include for returned resources of type appStoreReviewDetails | 
 **fieldsAppClipDefaultExperiences** | **[]string** | the fields to include for returned resources of type appClipDefaultExperiences | 
 **fieldsRoutingAppCoverages** | **[]string** | the fields to include for returned resources of type routingAppCoverages | 
 **fieldsAppStoreVersionPhasedReleases** | **[]string** | the fields to include for returned resources of type appStoreVersionPhasedReleases | 
 **fieldsBuilds** | **[]string** | the fields to include for returned resources of type builds | 
 **fieldsAppStoreVersionLocalizations** | **[]string** | the fields to include for returned resources of type appStoreVersionLocalizations | 
 **limitAppStoreVersionExperiments** | **int32** | maximum number of related appStoreVersionExperiments returned (when they are included) | 
 **limitAppStoreVersionLocalizations** | **int32** | maximum number of related appStoreVersionLocalizations returned (when they are included) | 

### Return type

[**AppStoreVersionResponse**](AppStoreVersionResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppStoreVersionsRoutingAppCoverageGetToOneRelated

> RoutingAppCoverageResponse AppStoreVersionsRoutingAppCoverageGetToOneRelated(ctx, id).FieldsRoutingAppCoverages(fieldsRoutingAppCoverages).Execute()



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
    fieldsRoutingAppCoverages := []string{"FieldsRoutingAppCoverages_example"} // []string | the fields to include for returned resources of type routingAppCoverages (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppStoreVersionsApi.AppStoreVersionsRoutingAppCoverageGetToOneRelated(context.Background(), id).FieldsRoutingAppCoverages(fieldsRoutingAppCoverages).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppStoreVersionsApi.AppStoreVersionsRoutingAppCoverageGetToOneRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppStoreVersionsRoutingAppCoverageGetToOneRelated`: RoutingAppCoverageResponse
    fmt.Fprintf(os.Stdout, "Response from `AppStoreVersionsApi.AppStoreVersionsRoutingAppCoverageGetToOneRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppStoreVersionsRoutingAppCoverageGetToOneRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsRoutingAppCoverages** | **[]string** | the fields to include for returned resources of type routingAppCoverages | 

### Return type

[**RoutingAppCoverageResponse**](RoutingAppCoverageResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppStoreVersionsUpdateInstance

> AppStoreVersionResponse AppStoreVersionsUpdateInstance(ctx, id).AppStoreVersionUpdateRequest(appStoreVersionUpdateRequest).Execute()



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
    appStoreVersionUpdateRequest := *openapiclient.NewAppStoreVersionUpdateRequest(*openapiclient.NewAppStoreVersionUpdateRequestData("Type_example", "Id_example")) // AppStoreVersionUpdateRequest | AppStoreVersion representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppStoreVersionsApi.AppStoreVersionsUpdateInstance(context.Background(), id).AppStoreVersionUpdateRequest(appStoreVersionUpdateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppStoreVersionsApi.AppStoreVersionsUpdateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppStoreVersionsUpdateInstance`: AppStoreVersionResponse
    fmt.Fprintf(os.Stdout, "Response from `AppStoreVersionsApi.AppStoreVersionsUpdateInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppStoreVersionsUpdateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **appStoreVersionUpdateRequest** | [**AppStoreVersionUpdateRequest**](AppStoreVersionUpdateRequest.md) | AppStoreVersion representation | 

### Return type

[**AppStoreVersionResponse**](AppStoreVersionResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

