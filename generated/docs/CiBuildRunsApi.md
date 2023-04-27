# \CiBuildRunsApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**CiBuildRunsActionsGetToManyRelated**](CiBuildRunsApi.md#CiBuildRunsActionsGetToManyRelated) | **Get** /v1/ciBuildRuns/{id}/actions | 
[**CiBuildRunsBuildsGetToManyRelated**](CiBuildRunsApi.md#CiBuildRunsBuildsGetToManyRelated) | **Get** /v1/ciBuildRuns/{id}/builds | 
[**CiBuildRunsCreateInstance**](CiBuildRunsApi.md#CiBuildRunsCreateInstance) | **Post** /v1/ciBuildRuns | 
[**CiBuildRunsGetInstance**](CiBuildRunsApi.md#CiBuildRunsGetInstance) | **Get** /v1/ciBuildRuns/{id} | 



## CiBuildRunsActionsGetToManyRelated

> CiBuildActionsResponse CiBuildRunsActionsGetToManyRelated(ctx, id).FieldsCiBuildRuns(fieldsCiBuildRuns).FieldsCiBuildActions(fieldsCiBuildActions).Limit(limit).Include(include).Execute()



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
    fieldsCiBuildRuns := []string{"FieldsCiBuildRuns_example"} // []string | the fields to include for returned resources of type ciBuildRuns (optional)
    fieldsCiBuildActions := []string{"FieldsCiBuildActions_example"} // []string | the fields to include for returned resources of type ciBuildActions (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.CiBuildRunsApi.CiBuildRunsActionsGetToManyRelated(context.Background(), id).FieldsCiBuildRuns(fieldsCiBuildRuns).FieldsCiBuildActions(fieldsCiBuildActions).Limit(limit).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `CiBuildRunsApi.CiBuildRunsActionsGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `CiBuildRunsActionsGetToManyRelated`: CiBuildActionsResponse
    fmt.Fprintf(os.Stdout, "Response from `CiBuildRunsApi.CiBuildRunsActionsGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiCiBuildRunsActionsGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsCiBuildRuns** | **[]string** | the fields to include for returned resources of type ciBuildRuns | 
 **fieldsCiBuildActions** | **[]string** | the fields to include for returned resources of type ciBuildActions | 
 **limit** | **int32** | maximum resources per page | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**CiBuildActionsResponse**](CiBuildActionsResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## CiBuildRunsBuildsGetToManyRelated

> BuildsResponse CiBuildRunsBuildsGetToManyRelated(ctx, id).FilterBetaAppReviewSubmissionBetaReviewState(filterBetaAppReviewSubmissionBetaReviewState).FilterBuildAudienceType(filterBuildAudienceType).FilterExpired(filterExpired).FilterPreReleaseVersionPlatform(filterPreReleaseVersionPlatform).FilterPreReleaseVersionVersion(filterPreReleaseVersionVersion).FilterProcessingState(filterProcessingState).FilterUsesNonExemptEncryption(filterUsesNonExemptEncryption).FilterVersion(filterVersion).FilterApp(filterApp).FilterAppStoreVersion(filterAppStoreVersion).FilterBetaGroups(filterBetaGroups).FilterPreReleaseVersion(filterPreReleaseVersion).FilterId(filterId).Sort(sort).FieldsBuildBundles(fieldsBuildBundles).FieldsBuildIcons(fieldsBuildIcons).FieldsBetaAppReviewSubmissions(fieldsBetaAppReviewSubmissions).FieldsBuildBetaDetails(fieldsBuildBetaDetails).FieldsBetaTesters(fieldsBetaTesters).FieldsPreReleaseVersions(fieldsPreReleaseVersions).FieldsBetaBuildLocalizations(fieldsBetaBuildLocalizations).FieldsAppStoreVersions(fieldsAppStoreVersions).FieldsAppEncryptionDeclarations(fieldsAppEncryptionDeclarations).FieldsApps(fieldsApps).FieldsBuilds(fieldsBuilds).FieldsBetaGroups(fieldsBetaGroups).Limit(limit).LimitIndividualTesters(limitIndividualTesters).LimitBetaGroups(limitBetaGroups).LimitBetaBuildLocalizations(limitBetaBuildLocalizations).LimitIcons(limitIcons).LimitBuildBundles(limitBuildBundles).Include(include).Execute()



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
    filterBetaAppReviewSubmissionBetaReviewState := []string{"FilterBetaAppReviewSubmissionBetaReviewState_example"} // []string | filter by attribute 'betaAppReviewSubmission.betaReviewState' (optional)
    filterBuildAudienceType := []string{"FilterBuildAudienceType_example"} // []string | filter by attribute 'buildAudienceType' (optional)
    filterExpired := []string{"Inner_example"} // []string | filter by attribute 'expired' (optional)
    filterPreReleaseVersionPlatform := []string{"FilterPreReleaseVersionPlatform_example"} // []string | filter by attribute 'preReleaseVersion.platform' (optional)
    filterPreReleaseVersionVersion := []string{"Inner_example"} // []string | filter by attribute 'preReleaseVersion.version' (optional)
    filterProcessingState := []string{"FilterProcessingState_example"} // []string | filter by attribute 'processingState' (optional)
    filterUsesNonExemptEncryption := []string{"Inner_example"} // []string | filter by attribute 'usesNonExemptEncryption' (optional)
    filterVersion := []string{"Inner_example"} // []string | filter by attribute 'version' (optional)
    filterApp := []string{"Inner_example"} // []string | filter by id(s) of related 'app' (optional)
    filterAppStoreVersion := []string{"Inner_example"} // []string | filter by id(s) of related 'appStoreVersion' (optional)
    filterBetaGroups := []string{"Inner_example"} // []string | filter by id(s) of related 'betaGroups' (optional)
    filterPreReleaseVersion := []string{"Inner_example"} // []string | filter by id(s) of related 'preReleaseVersion' (optional)
    filterId := []string{"Inner_example"} // []string | filter by id(s) (optional)
    sort := []string{"Sort_example"} // []string | comma-separated list of sort expressions; resources will be sorted as specified (optional)
    fieldsBuildBundles := []string{"FieldsBuildBundles_example"} // []string | the fields to include for returned resources of type buildBundles (optional)
    fieldsBuildIcons := []string{"FieldsBuildIcons_example"} // []string | the fields to include for returned resources of type buildIcons (optional)
    fieldsBetaAppReviewSubmissions := []string{"FieldsBetaAppReviewSubmissions_example"} // []string | the fields to include for returned resources of type betaAppReviewSubmissions (optional)
    fieldsBuildBetaDetails := []string{"FieldsBuildBetaDetails_example"} // []string | the fields to include for returned resources of type buildBetaDetails (optional)
    fieldsBetaTesters := []string{"FieldsBetaTesters_example"} // []string | the fields to include for returned resources of type betaTesters (optional)
    fieldsPreReleaseVersions := []string{"FieldsPreReleaseVersions_example"} // []string | the fields to include for returned resources of type preReleaseVersions (optional)
    fieldsBetaBuildLocalizations := []string{"FieldsBetaBuildLocalizations_example"} // []string | the fields to include for returned resources of type betaBuildLocalizations (optional)
    fieldsAppStoreVersions := []string{"FieldsAppStoreVersions_example"} // []string | the fields to include for returned resources of type appStoreVersions (optional)
    fieldsAppEncryptionDeclarations := []string{"FieldsAppEncryptionDeclarations_example"} // []string | the fields to include for returned resources of type appEncryptionDeclarations (optional)
    fieldsApps := []string{"FieldsApps_example"} // []string | the fields to include for returned resources of type apps (optional)
    fieldsBuilds := []string{"FieldsBuilds_example"} // []string | the fields to include for returned resources of type builds (optional)
    fieldsBetaGroups := []string{"FieldsBetaGroups_example"} // []string | the fields to include for returned resources of type betaGroups (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    limitIndividualTesters := int32(56) // int32 | maximum number of related individualTesters returned (when they are included) (optional)
    limitBetaGroups := int32(56) // int32 | maximum number of related betaGroups returned (when they are included) (optional)
    limitBetaBuildLocalizations := int32(56) // int32 | maximum number of related betaBuildLocalizations returned (when they are included) (optional)
    limitIcons := int32(56) // int32 | maximum number of related icons returned (when they are included) (optional)
    limitBuildBundles := int32(56) // int32 | maximum number of related buildBundles returned (when they are included) (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.CiBuildRunsApi.CiBuildRunsBuildsGetToManyRelated(context.Background(), id).FilterBetaAppReviewSubmissionBetaReviewState(filterBetaAppReviewSubmissionBetaReviewState).FilterBuildAudienceType(filterBuildAudienceType).FilterExpired(filterExpired).FilterPreReleaseVersionPlatform(filterPreReleaseVersionPlatform).FilterPreReleaseVersionVersion(filterPreReleaseVersionVersion).FilterProcessingState(filterProcessingState).FilterUsesNonExemptEncryption(filterUsesNonExemptEncryption).FilterVersion(filterVersion).FilterApp(filterApp).FilterAppStoreVersion(filterAppStoreVersion).FilterBetaGroups(filterBetaGroups).FilterPreReleaseVersion(filterPreReleaseVersion).FilterId(filterId).Sort(sort).FieldsBuildBundles(fieldsBuildBundles).FieldsBuildIcons(fieldsBuildIcons).FieldsBetaAppReviewSubmissions(fieldsBetaAppReviewSubmissions).FieldsBuildBetaDetails(fieldsBuildBetaDetails).FieldsBetaTesters(fieldsBetaTesters).FieldsPreReleaseVersions(fieldsPreReleaseVersions).FieldsBetaBuildLocalizations(fieldsBetaBuildLocalizations).FieldsAppStoreVersions(fieldsAppStoreVersions).FieldsAppEncryptionDeclarations(fieldsAppEncryptionDeclarations).FieldsApps(fieldsApps).FieldsBuilds(fieldsBuilds).FieldsBetaGroups(fieldsBetaGroups).Limit(limit).LimitIndividualTesters(limitIndividualTesters).LimitBetaGroups(limitBetaGroups).LimitBetaBuildLocalizations(limitBetaBuildLocalizations).LimitIcons(limitIcons).LimitBuildBundles(limitBuildBundles).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `CiBuildRunsApi.CiBuildRunsBuildsGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `CiBuildRunsBuildsGetToManyRelated`: BuildsResponse
    fmt.Fprintf(os.Stdout, "Response from `CiBuildRunsApi.CiBuildRunsBuildsGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiCiBuildRunsBuildsGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **filterBetaAppReviewSubmissionBetaReviewState** | **[]string** | filter by attribute &#39;betaAppReviewSubmission.betaReviewState&#39; | 
 **filterBuildAudienceType** | **[]string** | filter by attribute &#39;buildAudienceType&#39; | 
 **filterExpired** | **[]string** | filter by attribute &#39;expired&#39; | 
 **filterPreReleaseVersionPlatform** | **[]string** | filter by attribute &#39;preReleaseVersion.platform&#39; | 
 **filterPreReleaseVersionVersion** | **[]string** | filter by attribute &#39;preReleaseVersion.version&#39; | 
 **filterProcessingState** | **[]string** | filter by attribute &#39;processingState&#39; | 
 **filterUsesNonExemptEncryption** | **[]string** | filter by attribute &#39;usesNonExemptEncryption&#39; | 
 **filterVersion** | **[]string** | filter by attribute &#39;version&#39; | 
 **filterApp** | **[]string** | filter by id(s) of related &#39;app&#39; | 
 **filterAppStoreVersion** | **[]string** | filter by id(s) of related &#39;appStoreVersion&#39; | 
 **filterBetaGroups** | **[]string** | filter by id(s) of related &#39;betaGroups&#39; | 
 **filterPreReleaseVersion** | **[]string** | filter by id(s) of related &#39;preReleaseVersion&#39; | 
 **filterId** | **[]string** | filter by id(s) | 
 **sort** | **[]string** | comma-separated list of sort expressions; resources will be sorted as specified | 
 **fieldsBuildBundles** | **[]string** | the fields to include for returned resources of type buildBundles | 
 **fieldsBuildIcons** | **[]string** | the fields to include for returned resources of type buildIcons | 
 **fieldsBetaAppReviewSubmissions** | **[]string** | the fields to include for returned resources of type betaAppReviewSubmissions | 
 **fieldsBuildBetaDetails** | **[]string** | the fields to include for returned resources of type buildBetaDetails | 
 **fieldsBetaTesters** | **[]string** | the fields to include for returned resources of type betaTesters | 
 **fieldsPreReleaseVersions** | **[]string** | the fields to include for returned resources of type preReleaseVersions | 
 **fieldsBetaBuildLocalizations** | **[]string** | the fields to include for returned resources of type betaBuildLocalizations | 
 **fieldsAppStoreVersions** | **[]string** | the fields to include for returned resources of type appStoreVersions | 
 **fieldsAppEncryptionDeclarations** | **[]string** | the fields to include for returned resources of type appEncryptionDeclarations | 
 **fieldsApps** | **[]string** | the fields to include for returned resources of type apps | 
 **fieldsBuilds** | **[]string** | the fields to include for returned resources of type builds | 
 **fieldsBetaGroups** | **[]string** | the fields to include for returned resources of type betaGroups | 
 **limit** | **int32** | maximum resources per page | 
 **limitIndividualTesters** | **int32** | maximum number of related individualTesters returned (when they are included) | 
 **limitBetaGroups** | **int32** | maximum number of related betaGroups returned (when they are included) | 
 **limitBetaBuildLocalizations** | **int32** | maximum number of related betaBuildLocalizations returned (when they are included) | 
 **limitIcons** | **int32** | maximum number of related icons returned (when they are included) | 
 **limitBuildBundles** | **int32** | maximum number of related buildBundles returned (when they are included) | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**BuildsResponse**](BuildsResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## CiBuildRunsCreateInstance

> CiBuildRunResponse CiBuildRunsCreateInstance(ctx).CiBuildRunCreateRequest(ciBuildRunCreateRequest).Execute()



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
    ciBuildRunCreateRequest := *openapiclient.NewCiBuildRunCreateRequest(*openapiclient.NewCiBuildRunCreateRequestData("Type_example")) // CiBuildRunCreateRequest | CiBuildRun representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.CiBuildRunsApi.CiBuildRunsCreateInstance(context.Background()).CiBuildRunCreateRequest(ciBuildRunCreateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `CiBuildRunsApi.CiBuildRunsCreateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `CiBuildRunsCreateInstance`: CiBuildRunResponse
    fmt.Fprintf(os.Stdout, "Response from `CiBuildRunsApi.CiBuildRunsCreateInstance`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiCiBuildRunsCreateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ciBuildRunCreateRequest** | [**CiBuildRunCreateRequest**](CiBuildRunCreateRequest.md) | CiBuildRun representation | 

### Return type

[**CiBuildRunResponse**](CiBuildRunResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## CiBuildRunsGetInstance

> CiBuildRunResponse CiBuildRunsGetInstance(ctx, id).FieldsCiBuildRuns(fieldsCiBuildRuns).Include(include).FieldsCiBuildActions(fieldsCiBuildActions).FieldsBuilds(fieldsBuilds).LimitBuilds(limitBuilds).Execute()



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
    fieldsCiBuildRuns := []string{"FieldsCiBuildRuns_example"} // []string | the fields to include for returned resources of type ciBuildRuns (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)
    fieldsCiBuildActions := []string{"FieldsCiBuildActions_example"} // []string | the fields to include for returned resources of type ciBuildActions (optional)
    fieldsBuilds := []string{"FieldsBuilds_example"} // []string | the fields to include for returned resources of type builds (optional)
    limitBuilds := int32(56) // int32 | maximum number of related builds returned (when they are included) (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.CiBuildRunsApi.CiBuildRunsGetInstance(context.Background(), id).FieldsCiBuildRuns(fieldsCiBuildRuns).Include(include).FieldsCiBuildActions(fieldsCiBuildActions).FieldsBuilds(fieldsBuilds).LimitBuilds(limitBuilds).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `CiBuildRunsApi.CiBuildRunsGetInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `CiBuildRunsGetInstance`: CiBuildRunResponse
    fmt.Fprintf(os.Stdout, "Response from `CiBuildRunsApi.CiBuildRunsGetInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiCiBuildRunsGetInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsCiBuildRuns** | **[]string** | the fields to include for returned resources of type ciBuildRuns | 
 **include** | **[]string** | comma-separated list of relationships to include | 
 **fieldsCiBuildActions** | **[]string** | the fields to include for returned resources of type ciBuildActions | 
 **fieldsBuilds** | **[]string** | the fields to include for returned resources of type builds | 
 **limitBuilds** | **int32** | maximum number of related builds returned (when they are included) | 

### Return type

[**CiBuildRunResponse**](CiBuildRunResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

