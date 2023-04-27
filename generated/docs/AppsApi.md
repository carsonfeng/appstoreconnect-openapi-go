# \AppsApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**AppsAppAvailabilityGetToOneRelated**](AppsApi.md#AppsAppAvailabilityGetToOneRelated) | **Get** /v1/apps/{id}/appAvailability | 
[**AppsAppClipsGetToManyRelated**](AppsApi.md#AppsAppClipsGetToManyRelated) | **Get** /v1/apps/{id}/appClips | 
[**AppsAppCustomProductPagesGetToManyRelated**](AppsApi.md#AppsAppCustomProductPagesGetToManyRelated) | **Get** /v1/apps/{id}/appCustomProductPages | 
[**AppsAppEventsGetToManyRelated**](AppsApi.md#AppsAppEventsGetToManyRelated) | **Get** /v1/apps/{id}/appEvents | 
[**AppsAppInfosGetToManyRelated**](AppsApi.md#AppsAppInfosGetToManyRelated) | **Get** /v1/apps/{id}/appInfos | 
[**AppsAppPricePointsGetToManyRelated**](AppsApi.md#AppsAppPricePointsGetToManyRelated) | **Get** /v1/apps/{id}/appPricePoints | 
[**AppsAppPriceScheduleGetToOneRelated**](AppsApi.md#AppsAppPriceScheduleGetToOneRelated) | **Get** /v1/apps/{id}/appPriceSchedule | 
[**AppsAppStoreVersionsGetToManyRelated**](AppsApi.md#AppsAppStoreVersionsGetToManyRelated) | **Get** /v1/apps/{id}/appStoreVersions | 
[**AppsAvailableTerritoriesGetToManyRelated**](AppsApi.md#AppsAvailableTerritoriesGetToManyRelated) | **Get** /v1/apps/{id}/availableTerritories | 
[**AppsBetaAppLocalizationsGetToManyRelated**](AppsApi.md#AppsBetaAppLocalizationsGetToManyRelated) | **Get** /v1/apps/{id}/betaAppLocalizations | 
[**AppsBetaAppReviewDetailGetToOneRelated**](AppsApi.md#AppsBetaAppReviewDetailGetToOneRelated) | **Get** /v1/apps/{id}/betaAppReviewDetail | 
[**AppsBetaGroupsGetToManyRelated**](AppsApi.md#AppsBetaGroupsGetToManyRelated) | **Get** /v1/apps/{id}/betaGroups | 
[**AppsBetaLicenseAgreementGetToOneRelated**](AppsApi.md#AppsBetaLicenseAgreementGetToOneRelated) | **Get** /v1/apps/{id}/betaLicenseAgreement | 
[**AppsBetaTestersDeleteToManyRelationship**](AppsApi.md#AppsBetaTestersDeleteToManyRelationship) | **Delete** /v1/apps/{id}/relationships/betaTesters | 
[**AppsBuildsGetToManyRelated**](AppsApi.md#AppsBuildsGetToManyRelated) | **Get** /v1/apps/{id}/builds | 
[**AppsCiProductGetToOneRelated**](AppsApi.md#AppsCiProductGetToOneRelated) | **Get** /v1/apps/{id}/ciProduct | 
[**AppsCustomerReviewsGetToManyRelated**](AppsApi.md#AppsCustomerReviewsGetToManyRelated) | **Get** /v1/apps/{id}/customerReviews | 
[**AppsEndUserLicenseAgreementGetToOneRelated**](AppsApi.md#AppsEndUserLicenseAgreementGetToOneRelated) | **Get** /v1/apps/{id}/endUserLicenseAgreement | 
[**AppsGameCenterEnabledVersionsGetToManyRelated**](AppsApi.md#AppsGameCenterEnabledVersionsGetToManyRelated) | **Get** /v1/apps/{id}/gameCenterEnabledVersions | 
[**AppsGetCollection**](AppsApi.md#AppsGetCollection) | **Get** /v1/apps | 
[**AppsGetInstance**](AppsApi.md#AppsGetInstance) | **Get** /v1/apps/{id} | 
[**AppsInAppPurchasesGetToManyRelated**](AppsApi.md#AppsInAppPurchasesGetToManyRelated) | **Get** /v1/apps/{id}/inAppPurchases | 
[**AppsInAppPurchasesV2GetToManyRelated**](AppsApi.md#AppsInAppPurchasesV2GetToManyRelated) | **Get** /v1/apps/{id}/inAppPurchasesV2 | 
[**AppsPerfPowerMetricsGetToManyRelated**](AppsApi.md#AppsPerfPowerMetricsGetToManyRelated) | **Get** /v1/apps/{id}/perfPowerMetrics | 
[**AppsPreOrderGetToOneRelated**](AppsApi.md#AppsPreOrderGetToOneRelated) | **Get** /v1/apps/{id}/preOrder | 
[**AppsPreReleaseVersionsGetToManyRelated**](AppsApi.md#AppsPreReleaseVersionsGetToManyRelated) | **Get** /v1/apps/{id}/preReleaseVersions | 
[**AppsPricePointsGetToManyRelated**](AppsApi.md#AppsPricePointsGetToManyRelated) | **Get** /v1/apps/{id}/pricePoints | 
[**AppsPricesGetToManyRelated**](AppsApi.md#AppsPricesGetToManyRelated) | **Get** /v1/apps/{id}/prices | 
[**AppsPromotedPurchasesGetToManyRelated**](AppsApi.md#AppsPromotedPurchasesGetToManyRelated) | **Get** /v1/apps/{id}/promotedPurchases | 
[**AppsPromotedPurchasesGetToManyRelationship**](AppsApi.md#AppsPromotedPurchasesGetToManyRelationship) | **Get** /v1/apps/{id}/relationships/promotedPurchases | 
[**AppsPromotedPurchasesReplaceToManyRelationship**](AppsApi.md#AppsPromotedPurchasesReplaceToManyRelationship) | **Patch** /v1/apps/{id}/relationships/promotedPurchases | 
[**AppsReviewSubmissionsGetToManyRelated**](AppsApi.md#AppsReviewSubmissionsGetToManyRelated) | **Get** /v1/apps/{id}/reviewSubmissions | 
[**AppsSubscriptionGracePeriodGetToOneRelated**](AppsApi.md#AppsSubscriptionGracePeriodGetToOneRelated) | **Get** /v1/apps/{id}/subscriptionGracePeriod | 
[**AppsSubscriptionGroupsGetToManyRelated**](AppsApi.md#AppsSubscriptionGroupsGetToManyRelated) | **Get** /v1/apps/{id}/subscriptionGroups | 
[**AppsUpdateInstance**](AppsApi.md#AppsUpdateInstance) | **Patch** /v1/apps/{id} | 



## AppsAppAvailabilityGetToOneRelated

> AppAvailabilityResponse AppsAppAvailabilityGetToOneRelated(ctx, id).FieldsAppAvailabilities(fieldsAppAvailabilities).FieldsApps(fieldsApps).FieldsTerritories(fieldsTerritories).LimitAvailableTerritories(limitAvailableTerritories).Include(include).Execute()



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
    fieldsAppAvailabilities := []string{"FieldsAppAvailabilities_example"} // []string | the fields to include for returned resources of type appAvailabilities (optional)
    fieldsApps := []string{"FieldsApps_example"} // []string | the fields to include for returned resources of type apps (optional)
    fieldsTerritories := []string{"FieldsTerritories_example"} // []string | the fields to include for returned resources of type territories (optional)
    limitAvailableTerritories := int32(56) // int32 | maximum number of related availableTerritories returned (when they are included) (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppsApi.AppsAppAvailabilityGetToOneRelated(context.Background(), id).FieldsAppAvailabilities(fieldsAppAvailabilities).FieldsApps(fieldsApps).FieldsTerritories(fieldsTerritories).LimitAvailableTerritories(limitAvailableTerritories).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppsApi.AppsAppAvailabilityGetToOneRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppsAppAvailabilityGetToOneRelated`: AppAvailabilityResponse
    fmt.Fprintf(os.Stdout, "Response from `AppsApi.AppsAppAvailabilityGetToOneRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppsAppAvailabilityGetToOneRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsAppAvailabilities** | **[]string** | the fields to include for returned resources of type appAvailabilities | 
 **fieldsApps** | **[]string** | the fields to include for returned resources of type apps | 
 **fieldsTerritories** | **[]string** | the fields to include for returned resources of type territories | 
 **limitAvailableTerritories** | **int32** | maximum number of related availableTerritories returned (when they are included) | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**AppAvailabilityResponse**](AppAvailabilityResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppsAppClipsGetToManyRelated

> AppClipsResponse AppsAppClipsGetToManyRelated(ctx, id).FilterBundleId(filterBundleId).FieldsAppClips(fieldsAppClips).FieldsApps(fieldsApps).FieldsAppClipDefaultExperiences(fieldsAppClipDefaultExperiences).Limit(limit).LimitAppClipDefaultExperiences(limitAppClipDefaultExperiences).Include(include).Execute()



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
    filterBundleId := []string{"Inner_example"} // []string | filter by attribute 'bundleId' (optional)
    fieldsAppClips := []string{"FieldsAppClips_example"} // []string | the fields to include for returned resources of type appClips (optional)
    fieldsApps := []string{"FieldsApps_example"} // []string | the fields to include for returned resources of type apps (optional)
    fieldsAppClipDefaultExperiences := []string{"FieldsAppClipDefaultExperiences_example"} // []string | the fields to include for returned resources of type appClipDefaultExperiences (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    limitAppClipDefaultExperiences := int32(56) // int32 | maximum number of related appClipDefaultExperiences returned (when they are included) (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppsApi.AppsAppClipsGetToManyRelated(context.Background(), id).FilterBundleId(filterBundleId).FieldsAppClips(fieldsAppClips).FieldsApps(fieldsApps).FieldsAppClipDefaultExperiences(fieldsAppClipDefaultExperiences).Limit(limit).LimitAppClipDefaultExperiences(limitAppClipDefaultExperiences).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppsApi.AppsAppClipsGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppsAppClipsGetToManyRelated`: AppClipsResponse
    fmt.Fprintf(os.Stdout, "Response from `AppsApi.AppsAppClipsGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppsAppClipsGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **filterBundleId** | **[]string** | filter by attribute &#39;bundleId&#39; | 
 **fieldsAppClips** | **[]string** | the fields to include for returned resources of type appClips | 
 **fieldsApps** | **[]string** | the fields to include for returned resources of type apps | 
 **fieldsAppClipDefaultExperiences** | **[]string** | the fields to include for returned resources of type appClipDefaultExperiences | 
 **limit** | **int32** | maximum resources per page | 
 **limitAppClipDefaultExperiences** | **int32** | maximum number of related appClipDefaultExperiences returned (when they are included) | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**AppClipsResponse**](AppClipsResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppsAppCustomProductPagesGetToManyRelated

> AppCustomProductPagesResponse AppsAppCustomProductPagesGetToManyRelated(ctx, id).FilterVisible(filterVisible).FieldsAppCustomProductPages(fieldsAppCustomProductPages).FieldsAppCustomProductPageVersions(fieldsAppCustomProductPageVersions).FieldsApps(fieldsApps).Limit(limit).LimitAppCustomProductPageVersions(limitAppCustomProductPageVersions).Include(include).Execute()



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
    filterVisible := []string{"Inner_example"} // []string | filter by attribute 'visible' (optional)
    fieldsAppCustomProductPages := []string{"FieldsAppCustomProductPages_example"} // []string | the fields to include for returned resources of type appCustomProductPages (optional)
    fieldsAppCustomProductPageVersions := []string{"FieldsAppCustomProductPageVersions_example"} // []string | the fields to include for returned resources of type appCustomProductPageVersions (optional)
    fieldsApps := []string{"FieldsApps_example"} // []string | the fields to include for returned resources of type apps (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    limitAppCustomProductPageVersions := int32(56) // int32 | maximum number of related appCustomProductPageVersions returned (when they are included) (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppsApi.AppsAppCustomProductPagesGetToManyRelated(context.Background(), id).FilterVisible(filterVisible).FieldsAppCustomProductPages(fieldsAppCustomProductPages).FieldsAppCustomProductPageVersions(fieldsAppCustomProductPageVersions).FieldsApps(fieldsApps).Limit(limit).LimitAppCustomProductPageVersions(limitAppCustomProductPageVersions).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppsApi.AppsAppCustomProductPagesGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppsAppCustomProductPagesGetToManyRelated`: AppCustomProductPagesResponse
    fmt.Fprintf(os.Stdout, "Response from `AppsApi.AppsAppCustomProductPagesGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppsAppCustomProductPagesGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **filterVisible** | **[]string** | filter by attribute &#39;visible&#39; | 
 **fieldsAppCustomProductPages** | **[]string** | the fields to include for returned resources of type appCustomProductPages | 
 **fieldsAppCustomProductPageVersions** | **[]string** | the fields to include for returned resources of type appCustomProductPageVersions | 
 **fieldsApps** | **[]string** | the fields to include for returned resources of type apps | 
 **limit** | **int32** | maximum resources per page | 
 **limitAppCustomProductPageVersions** | **int32** | maximum number of related appCustomProductPageVersions returned (when they are included) | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**AppCustomProductPagesResponse**](AppCustomProductPagesResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppsAppEventsGetToManyRelated

> AppEventsResponse AppsAppEventsGetToManyRelated(ctx, id).FilterEventState(filterEventState).FilterId(filterId).FieldsAppEventLocalizations(fieldsAppEventLocalizations).FieldsAppEvents(fieldsAppEvents).Limit(limit).LimitLocalizations(limitLocalizations).Include(include).Execute()



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
    filterEventState := []string{"FilterEventState_example"} // []string | filter by attribute 'eventState' (optional)
    filterId := []string{"Inner_example"} // []string | filter by id(s) (optional)
    fieldsAppEventLocalizations := []string{"FieldsAppEventLocalizations_example"} // []string | the fields to include for returned resources of type appEventLocalizations (optional)
    fieldsAppEvents := []string{"FieldsAppEvents_example"} // []string | the fields to include for returned resources of type appEvents (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    limitLocalizations := int32(56) // int32 | maximum number of related localizations returned (when they are included) (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppsApi.AppsAppEventsGetToManyRelated(context.Background(), id).FilterEventState(filterEventState).FilterId(filterId).FieldsAppEventLocalizations(fieldsAppEventLocalizations).FieldsAppEvents(fieldsAppEvents).Limit(limit).LimitLocalizations(limitLocalizations).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppsApi.AppsAppEventsGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppsAppEventsGetToManyRelated`: AppEventsResponse
    fmt.Fprintf(os.Stdout, "Response from `AppsApi.AppsAppEventsGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppsAppEventsGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **filterEventState** | **[]string** | filter by attribute &#39;eventState&#39; | 
 **filterId** | **[]string** | filter by id(s) | 
 **fieldsAppEventLocalizations** | **[]string** | the fields to include for returned resources of type appEventLocalizations | 
 **fieldsAppEvents** | **[]string** | the fields to include for returned resources of type appEvents | 
 **limit** | **int32** | maximum resources per page | 
 **limitLocalizations** | **int32** | maximum number of related localizations returned (when they are included) | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**AppEventsResponse**](AppEventsResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppsAppInfosGetToManyRelated

> AppInfosResponse AppsAppInfosGetToManyRelated(ctx, id).FieldsAgeRatingDeclarations(fieldsAgeRatingDeclarations).FieldsAppInfos(fieldsAppInfos).FieldsAppInfoLocalizations(fieldsAppInfoLocalizations).FieldsAppCategories(fieldsAppCategories).FieldsApps(fieldsApps).Limit(limit).LimitAppInfoLocalizations(limitAppInfoLocalizations).Include(include).Execute()



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
    fieldsAppInfos := []string{"FieldsAppInfos_example"} // []string | the fields to include for returned resources of type appInfos (optional)
    fieldsAppInfoLocalizations := []string{"FieldsAppInfoLocalizations_example"} // []string | the fields to include for returned resources of type appInfoLocalizations (optional)
    fieldsAppCategories := []string{"FieldsAppCategories_example"} // []string | the fields to include for returned resources of type appCategories (optional)
    fieldsApps := []string{"FieldsApps_example"} // []string | the fields to include for returned resources of type apps (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    limitAppInfoLocalizations := int32(56) // int32 | maximum number of related appInfoLocalizations returned (when they are included) (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppsApi.AppsAppInfosGetToManyRelated(context.Background(), id).FieldsAgeRatingDeclarations(fieldsAgeRatingDeclarations).FieldsAppInfos(fieldsAppInfos).FieldsAppInfoLocalizations(fieldsAppInfoLocalizations).FieldsAppCategories(fieldsAppCategories).FieldsApps(fieldsApps).Limit(limit).LimitAppInfoLocalizations(limitAppInfoLocalizations).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppsApi.AppsAppInfosGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppsAppInfosGetToManyRelated`: AppInfosResponse
    fmt.Fprintf(os.Stdout, "Response from `AppsApi.AppsAppInfosGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppsAppInfosGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsAgeRatingDeclarations** | **[]string** | the fields to include for returned resources of type ageRatingDeclarations | 
 **fieldsAppInfos** | **[]string** | the fields to include for returned resources of type appInfos | 
 **fieldsAppInfoLocalizations** | **[]string** | the fields to include for returned resources of type appInfoLocalizations | 
 **fieldsAppCategories** | **[]string** | the fields to include for returned resources of type appCategories | 
 **fieldsApps** | **[]string** | the fields to include for returned resources of type apps | 
 **limit** | **int32** | maximum resources per page | 
 **limitAppInfoLocalizations** | **int32** | maximum number of related appInfoLocalizations returned (when they are included) | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**AppInfosResponse**](AppInfosResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppsAppPricePointsGetToManyRelated

> AppPricePointsV3Response AppsAppPricePointsGetToManyRelated(ctx, id).FilterTerritory(filterTerritory).FieldsAppPricePoints(fieldsAppPricePoints).FieldsApps(fieldsApps).FieldsTerritories(fieldsTerritories).Limit(limit).Include(include).Execute()



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
    filterTerritory := []string{"Inner_example"} // []string | filter by id(s) of related 'territory' (optional)
    fieldsAppPricePoints := []string{"FieldsAppPricePoints_example"} // []string | the fields to include for returned resources of type appPricePoints (optional)
    fieldsApps := []string{"FieldsApps_example"} // []string | the fields to include for returned resources of type apps (optional)
    fieldsTerritories := []string{"FieldsTerritories_example"} // []string | the fields to include for returned resources of type territories (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppsApi.AppsAppPricePointsGetToManyRelated(context.Background(), id).FilterTerritory(filterTerritory).FieldsAppPricePoints(fieldsAppPricePoints).FieldsApps(fieldsApps).FieldsTerritories(fieldsTerritories).Limit(limit).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppsApi.AppsAppPricePointsGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppsAppPricePointsGetToManyRelated`: AppPricePointsV3Response
    fmt.Fprintf(os.Stdout, "Response from `AppsApi.AppsAppPricePointsGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppsAppPricePointsGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **filterTerritory** | **[]string** | filter by id(s) of related &#39;territory&#39; | 
 **fieldsAppPricePoints** | **[]string** | the fields to include for returned resources of type appPricePoints | 
 **fieldsApps** | **[]string** | the fields to include for returned resources of type apps | 
 **fieldsTerritories** | **[]string** | the fields to include for returned resources of type territories | 
 **limit** | **int32** | maximum resources per page | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**AppPricePointsV3Response**](AppPricePointsV3Response.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json, text/csv

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppsAppPriceScheduleGetToOneRelated

> AppPriceScheduleResponse AppsAppPriceScheduleGetToOneRelated(ctx, id).FieldsAppPrices(fieldsAppPrices).FieldsAppPriceSchedules(fieldsAppPriceSchedules).FieldsApps(fieldsApps).FieldsTerritories(fieldsTerritories).LimitManualPrices(limitManualPrices).LimitAutomaticPrices(limitAutomaticPrices).Include(include).Execute()



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
    fieldsAppPrices := []string{"FieldsAppPrices_example"} // []string | the fields to include for returned resources of type appPrices (optional)
    fieldsAppPriceSchedules := []string{"FieldsAppPriceSchedules_example"} // []string | the fields to include for returned resources of type appPriceSchedules (optional)
    fieldsApps := []string{"FieldsApps_example"} // []string | the fields to include for returned resources of type apps (optional)
    fieldsTerritories := []string{"FieldsTerritories_example"} // []string | the fields to include for returned resources of type territories (optional)
    limitManualPrices := int32(56) // int32 | maximum number of related manualPrices returned (when they are included) (optional)
    limitAutomaticPrices := int32(56) // int32 | maximum number of related automaticPrices returned (when they are included) (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppsApi.AppsAppPriceScheduleGetToOneRelated(context.Background(), id).FieldsAppPrices(fieldsAppPrices).FieldsAppPriceSchedules(fieldsAppPriceSchedules).FieldsApps(fieldsApps).FieldsTerritories(fieldsTerritories).LimitManualPrices(limitManualPrices).LimitAutomaticPrices(limitAutomaticPrices).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppsApi.AppsAppPriceScheduleGetToOneRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppsAppPriceScheduleGetToOneRelated`: AppPriceScheduleResponse
    fmt.Fprintf(os.Stdout, "Response from `AppsApi.AppsAppPriceScheduleGetToOneRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppsAppPriceScheduleGetToOneRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsAppPrices** | **[]string** | the fields to include for returned resources of type appPrices | 
 **fieldsAppPriceSchedules** | **[]string** | the fields to include for returned resources of type appPriceSchedules | 
 **fieldsApps** | **[]string** | the fields to include for returned resources of type apps | 
 **fieldsTerritories** | **[]string** | the fields to include for returned resources of type territories | 
 **limitManualPrices** | **int32** | maximum number of related manualPrices returned (when they are included) | 
 **limitAutomaticPrices** | **int32** | maximum number of related automaticPrices returned (when they are included) | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**AppPriceScheduleResponse**](AppPriceScheduleResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppsAppStoreVersionsGetToManyRelated

> AppStoreVersionsResponse AppsAppStoreVersionsGetToManyRelated(ctx, id).FilterAppStoreState(filterAppStoreState).FilterPlatform(filterPlatform).FilterVersionString(filterVersionString).FilterId(filterId).FieldsAppStoreVersionExperiments(fieldsAppStoreVersionExperiments).FieldsAgeRatingDeclarations(fieldsAgeRatingDeclarations).FieldsAppStoreVersionSubmissions(fieldsAppStoreVersionSubmissions).FieldsAppStoreReviewDetails(fieldsAppStoreReviewDetails).FieldsAppStoreVersions(fieldsAppStoreVersions).FieldsApps(fieldsApps).FieldsRoutingAppCoverages(fieldsRoutingAppCoverages).FieldsAppClipDefaultExperiences(fieldsAppClipDefaultExperiences).FieldsAppStoreVersionPhasedReleases(fieldsAppStoreVersionPhasedReleases).FieldsBuilds(fieldsBuilds).FieldsAppStoreVersionLocalizations(fieldsAppStoreVersionLocalizations).Limit(limit).LimitAppStoreVersionLocalizations(limitAppStoreVersionLocalizations).LimitAppStoreVersionExperiments(limitAppStoreVersionExperiments).Include(include).Execute()



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
    filterAppStoreState := []string{"FilterAppStoreState_example"} // []string | filter by attribute 'appStoreState' (optional)
    filterPlatform := []string{"FilterPlatform_example"} // []string | filter by attribute 'platform' (optional)
    filterVersionString := []string{"Inner_example"} // []string | filter by attribute 'versionString' (optional)
    filterId := []string{"Inner_example"} // []string | filter by id(s) (optional)
    fieldsAppStoreVersionExperiments := []string{"FieldsAppStoreVersionExperiments_example"} // []string | the fields to include for returned resources of type appStoreVersionExperiments (optional)
    fieldsAgeRatingDeclarations := []string{"FieldsAgeRatingDeclarations_example"} // []string | the fields to include for returned resources of type ageRatingDeclarations (optional)
    fieldsAppStoreVersionSubmissions := []string{"FieldsAppStoreVersionSubmissions_example"} // []string | the fields to include for returned resources of type appStoreVersionSubmissions (optional)
    fieldsAppStoreReviewDetails := []string{"FieldsAppStoreReviewDetails_example"} // []string | the fields to include for returned resources of type appStoreReviewDetails (optional)
    fieldsAppStoreVersions := []string{"FieldsAppStoreVersions_example"} // []string | the fields to include for returned resources of type appStoreVersions (optional)
    fieldsApps := []string{"FieldsApps_example"} // []string | the fields to include for returned resources of type apps (optional)
    fieldsRoutingAppCoverages := []string{"FieldsRoutingAppCoverages_example"} // []string | the fields to include for returned resources of type routingAppCoverages (optional)
    fieldsAppClipDefaultExperiences := []string{"FieldsAppClipDefaultExperiences_example"} // []string | the fields to include for returned resources of type appClipDefaultExperiences (optional)
    fieldsAppStoreVersionPhasedReleases := []string{"FieldsAppStoreVersionPhasedReleases_example"} // []string | the fields to include for returned resources of type appStoreVersionPhasedReleases (optional)
    fieldsBuilds := []string{"FieldsBuilds_example"} // []string | the fields to include for returned resources of type builds (optional)
    fieldsAppStoreVersionLocalizations := []string{"FieldsAppStoreVersionLocalizations_example"} // []string | the fields to include for returned resources of type appStoreVersionLocalizations (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    limitAppStoreVersionLocalizations := int32(56) // int32 | maximum number of related appStoreVersionLocalizations returned (when they are included) (optional)
    limitAppStoreVersionExperiments := int32(56) // int32 | maximum number of related appStoreVersionExperiments returned (when they are included) (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppsApi.AppsAppStoreVersionsGetToManyRelated(context.Background(), id).FilterAppStoreState(filterAppStoreState).FilterPlatform(filterPlatform).FilterVersionString(filterVersionString).FilterId(filterId).FieldsAppStoreVersionExperiments(fieldsAppStoreVersionExperiments).FieldsAgeRatingDeclarations(fieldsAgeRatingDeclarations).FieldsAppStoreVersionSubmissions(fieldsAppStoreVersionSubmissions).FieldsAppStoreReviewDetails(fieldsAppStoreReviewDetails).FieldsAppStoreVersions(fieldsAppStoreVersions).FieldsApps(fieldsApps).FieldsRoutingAppCoverages(fieldsRoutingAppCoverages).FieldsAppClipDefaultExperiences(fieldsAppClipDefaultExperiences).FieldsAppStoreVersionPhasedReleases(fieldsAppStoreVersionPhasedReleases).FieldsBuilds(fieldsBuilds).FieldsAppStoreVersionLocalizations(fieldsAppStoreVersionLocalizations).Limit(limit).LimitAppStoreVersionLocalizations(limitAppStoreVersionLocalizations).LimitAppStoreVersionExperiments(limitAppStoreVersionExperiments).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppsApi.AppsAppStoreVersionsGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppsAppStoreVersionsGetToManyRelated`: AppStoreVersionsResponse
    fmt.Fprintf(os.Stdout, "Response from `AppsApi.AppsAppStoreVersionsGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppsAppStoreVersionsGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **filterAppStoreState** | **[]string** | filter by attribute &#39;appStoreState&#39; | 
 **filterPlatform** | **[]string** | filter by attribute &#39;platform&#39; | 
 **filterVersionString** | **[]string** | filter by attribute &#39;versionString&#39; | 
 **filterId** | **[]string** | filter by id(s) | 
 **fieldsAppStoreVersionExperiments** | **[]string** | the fields to include for returned resources of type appStoreVersionExperiments | 
 **fieldsAgeRatingDeclarations** | **[]string** | the fields to include for returned resources of type ageRatingDeclarations | 
 **fieldsAppStoreVersionSubmissions** | **[]string** | the fields to include for returned resources of type appStoreVersionSubmissions | 
 **fieldsAppStoreReviewDetails** | **[]string** | the fields to include for returned resources of type appStoreReviewDetails | 
 **fieldsAppStoreVersions** | **[]string** | the fields to include for returned resources of type appStoreVersions | 
 **fieldsApps** | **[]string** | the fields to include for returned resources of type apps | 
 **fieldsRoutingAppCoverages** | **[]string** | the fields to include for returned resources of type routingAppCoverages | 
 **fieldsAppClipDefaultExperiences** | **[]string** | the fields to include for returned resources of type appClipDefaultExperiences | 
 **fieldsAppStoreVersionPhasedReleases** | **[]string** | the fields to include for returned resources of type appStoreVersionPhasedReleases | 
 **fieldsBuilds** | **[]string** | the fields to include for returned resources of type builds | 
 **fieldsAppStoreVersionLocalizations** | **[]string** | the fields to include for returned resources of type appStoreVersionLocalizations | 
 **limit** | **int32** | maximum resources per page | 
 **limitAppStoreVersionLocalizations** | **int32** | maximum number of related appStoreVersionLocalizations returned (when they are included) | 
 **limitAppStoreVersionExperiments** | **int32** | maximum number of related appStoreVersionExperiments returned (when they are included) | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**AppStoreVersionsResponse**](AppStoreVersionsResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppsAvailableTerritoriesGetToManyRelated

> TerritoriesResponse AppsAvailableTerritoriesGetToManyRelated(ctx, id).FieldsTerritories(fieldsTerritories).Limit(limit).Execute()



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
    fieldsTerritories := []string{"FieldsTerritories_example"} // []string | the fields to include for returned resources of type territories (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppsApi.AppsAvailableTerritoriesGetToManyRelated(context.Background(), id).FieldsTerritories(fieldsTerritories).Limit(limit).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppsApi.AppsAvailableTerritoriesGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppsAvailableTerritoriesGetToManyRelated`: TerritoriesResponse
    fmt.Fprintf(os.Stdout, "Response from `AppsApi.AppsAvailableTerritoriesGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppsAvailableTerritoriesGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsTerritories** | **[]string** | the fields to include for returned resources of type territories | 
 **limit** | **int32** | maximum resources per page | 

### Return type

[**TerritoriesResponse**](TerritoriesResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppsBetaAppLocalizationsGetToManyRelated

> BetaAppLocalizationsResponse AppsBetaAppLocalizationsGetToManyRelated(ctx, id).FieldsBetaAppLocalizations(fieldsBetaAppLocalizations).Limit(limit).Execute()



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
    fieldsBetaAppLocalizations := []string{"FieldsBetaAppLocalizations_example"} // []string | the fields to include for returned resources of type betaAppLocalizations (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppsApi.AppsBetaAppLocalizationsGetToManyRelated(context.Background(), id).FieldsBetaAppLocalizations(fieldsBetaAppLocalizations).Limit(limit).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppsApi.AppsBetaAppLocalizationsGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppsBetaAppLocalizationsGetToManyRelated`: BetaAppLocalizationsResponse
    fmt.Fprintf(os.Stdout, "Response from `AppsApi.AppsBetaAppLocalizationsGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppsBetaAppLocalizationsGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsBetaAppLocalizations** | **[]string** | the fields to include for returned resources of type betaAppLocalizations | 
 **limit** | **int32** | maximum resources per page | 

### Return type

[**BetaAppLocalizationsResponse**](BetaAppLocalizationsResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppsBetaAppReviewDetailGetToOneRelated

> BetaAppReviewDetailResponse AppsBetaAppReviewDetailGetToOneRelated(ctx, id).FieldsBetaAppReviewDetails(fieldsBetaAppReviewDetails).Execute()



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
    fieldsBetaAppReviewDetails := []string{"FieldsBetaAppReviewDetails_example"} // []string | the fields to include for returned resources of type betaAppReviewDetails (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppsApi.AppsBetaAppReviewDetailGetToOneRelated(context.Background(), id).FieldsBetaAppReviewDetails(fieldsBetaAppReviewDetails).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppsApi.AppsBetaAppReviewDetailGetToOneRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppsBetaAppReviewDetailGetToOneRelated`: BetaAppReviewDetailResponse
    fmt.Fprintf(os.Stdout, "Response from `AppsApi.AppsBetaAppReviewDetailGetToOneRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppsBetaAppReviewDetailGetToOneRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsBetaAppReviewDetails** | **[]string** | the fields to include for returned resources of type betaAppReviewDetails | 

### Return type

[**BetaAppReviewDetailResponse**](BetaAppReviewDetailResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppsBetaGroupsGetToManyRelated

> BetaGroupsResponse AppsBetaGroupsGetToManyRelated(ctx, id).FieldsBetaGroups(fieldsBetaGroups).Limit(limit).Execute()



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
    fieldsBetaGroups := []string{"FieldsBetaGroups_example"} // []string | the fields to include for returned resources of type betaGroups (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppsApi.AppsBetaGroupsGetToManyRelated(context.Background(), id).FieldsBetaGroups(fieldsBetaGroups).Limit(limit).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppsApi.AppsBetaGroupsGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppsBetaGroupsGetToManyRelated`: BetaGroupsResponse
    fmt.Fprintf(os.Stdout, "Response from `AppsApi.AppsBetaGroupsGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppsBetaGroupsGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsBetaGroups** | **[]string** | the fields to include for returned resources of type betaGroups | 
 **limit** | **int32** | maximum resources per page | 

### Return type

[**BetaGroupsResponse**](BetaGroupsResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppsBetaLicenseAgreementGetToOneRelated

> BetaLicenseAgreementResponse AppsBetaLicenseAgreementGetToOneRelated(ctx, id).FieldsBetaLicenseAgreements(fieldsBetaLicenseAgreements).Execute()



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
    fieldsBetaLicenseAgreements := []string{"FieldsBetaLicenseAgreements_example"} // []string | the fields to include for returned resources of type betaLicenseAgreements (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppsApi.AppsBetaLicenseAgreementGetToOneRelated(context.Background(), id).FieldsBetaLicenseAgreements(fieldsBetaLicenseAgreements).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppsApi.AppsBetaLicenseAgreementGetToOneRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppsBetaLicenseAgreementGetToOneRelated`: BetaLicenseAgreementResponse
    fmt.Fprintf(os.Stdout, "Response from `AppsApi.AppsBetaLicenseAgreementGetToOneRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppsBetaLicenseAgreementGetToOneRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsBetaLicenseAgreements** | **[]string** | the fields to include for returned resources of type betaLicenseAgreements | 

### Return type

[**BetaLicenseAgreementResponse**](BetaLicenseAgreementResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppsBetaTestersDeleteToManyRelationship

> AppsBetaTestersDeleteToManyRelationship(ctx, id).AppBetaTestersLinkagesRequest(appBetaTestersLinkagesRequest).Execute()



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
    appBetaTestersLinkagesRequest := *openapiclient.NewAppBetaTestersLinkagesRequest([]openapiclient.BetaGroupRelationshipsBetaTestersDataInner{*openapiclient.NewBetaGroupRelationshipsBetaTestersDataInner("Type_example", "Id_example")}) // AppBetaTestersLinkagesRequest | List of related linkages

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    r, err := apiClient.AppsApi.AppsBetaTestersDeleteToManyRelationship(context.Background(), id).AppBetaTestersLinkagesRequest(appBetaTestersLinkagesRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppsApi.AppsBetaTestersDeleteToManyRelationship``: %v\n", err)
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

Other parameters are passed through a pointer to a apiAppsBetaTestersDeleteToManyRelationshipRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **appBetaTestersLinkagesRequest** | [**AppBetaTestersLinkagesRequest**](AppBetaTestersLinkagesRequest.md) | List of related linkages | 

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


## AppsBuildsGetToManyRelated

> BuildsResponse AppsBuildsGetToManyRelated(ctx, id).FieldsBuilds(fieldsBuilds).Limit(limit).Execute()



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
    limit := int32(56) // int32 | maximum resources per page (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppsApi.AppsBuildsGetToManyRelated(context.Background(), id).FieldsBuilds(fieldsBuilds).Limit(limit).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppsApi.AppsBuildsGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppsBuildsGetToManyRelated`: BuildsResponse
    fmt.Fprintf(os.Stdout, "Response from `AppsApi.AppsBuildsGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppsBuildsGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsBuilds** | **[]string** | the fields to include for returned resources of type builds | 
 **limit** | **int32** | maximum resources per page | 

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


## AppsCiProductGetToOneRelated

> CiProductResponse AppsCiProductGetToOneRelated(ctx, id).FieldsCiProducts(fieldsCiProducts).FieldsApps(fieldsApps).FieldsScmRepositories(fieldsScmRepositories).FieldsBundleIds(fieldsBundleIds).LimitPrimaryRepositories(limitPrimaryRepositories).Include(include).Execute()



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
    fieldsCiProducts := []string{"FieldsCiProducts_example"} // []string | the fields to include for returned resources of type ciProducts (optional)
    fieldsApps := []string{"FieldsApps_example"} // []string | the fields to include for returned resources of type apps (optional)
    fieldsScmRepositories := []string{"FieldsScmRepositories_example"} // []string | the fields to include for returned resources of type scmRepositories (optional)
    fieldsBundleIds := []string{"FieldsBundleIds_example"} // []string | the fields to include for returned resources of type bundleIds (optional)
    limitPrimaryRepositories := int32(56) // int32 | maximum number of related primaryRepositories returned (when they are included) (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppsApi.AppsCiProductGetToOneRelated(context.Background(), id).FieldsCiProducts(fieldsCiProducts).FieldsApps(fieldsApps).FieldsScmRepositories(fieldsScmRepositories).FieldsBundleIds(fieldsBundleIds).LimitPrimaryRepositories(limitPrimaryRepositories).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppsApi.AppsCiProductGetToOneRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppsCiProductGetToOneRelated`: CiProductResponse
    fmt.Fprintf(os.Stdout, "Response from `AppsApi.AppsCiProductGetToOneRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppsCiProductGetToOneRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsCiProducts** | **[]string** | the fields to include for returned resources of type ciProducts | 
 **fieldsApps** | **[]string** | the fields to include for returned resources of type apps | 
 **fieldsScmRepositories** | **[]string** | the fields to include for returned resources of type scmRepositories | 
 **fieldsBundleIds** | **[]string** | the fields to include for returned resources of type bundleIds | 
 **limitPrimaryRepositories** | **int32** | maximum number of related primaryRepositories returned (when they are included) | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**CiProductResponse**](CiProductResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppsCustomerReviewsGetToManyRelated

> CustomerReviewsResponse AppsCustomerReviewsGetToManyRelated(ctx, id).FilterRating(filterRating).FilterTerritory(filterTerritory).ExistsPublishedResponse(existsPublishedResponse).Sort(sort).FieldsCustomerReviews(fieldsCustomerReviews).FieldsCustomerReviewResponses(fieldsCustomerReviewResponses).Limit(limit).Include(include).Execute()



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
    resp, r, err := apiClient.AppsApi.AppsCustomerReviewsGetToManyRelated(context.Background(), id).FilterRating(filterRating).FilterTerritory(filterTerritory).ExistsPublishedResponse(existsPublishedResponse).Sort(sort).FieldsCustomerReviews(fieldsCustomerReviews).FieldsCustomerReviewResponses(fieldsCustomerReviewResponses).Limit(limit).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppsApi.AppsCustomerReviewsGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppsCustomerReviewsGetToManyRelated`: CustomerReviewsResponse
    fmt.Fprintf(os.Stdout, "Response from `AppsApi.AppsCustomerReviewsGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppsCustomerReviewsGetToManyRelatedRequest struct via the builder pattern


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


## AppsEndUserLicenseAgreementGetToOneRelated

> EndUserLicenseAgreementResponse AppsEndUserLicenseAgreementGetToOneRelated(ctx, id).FieldsEndUserLicenseAgreements(fieldsEndUserLicenseAgreements).Execute()



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
    fieldsEndUserLicenseAgreements := []string{"FieldsEndUserLicenseAgreements_example"} // []string | the fields to include for returned resources of type endUserLicenseAgreements (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppsApi.AppsEndUserLicenseAgreementGetToOneRelated(context.Background(), id).FieldsEndUserLicenseAgreements(fieldsEndUserLicenseAgreements).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppsApi.AppsEndUserLicenseAgreementGetToOneRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppsEndUserLicenseAgreementGetToOneRelated`: EndUserLicenseAgreementResponse
    fmt.Fprintf(os.Stdout, "Response from `AppsApi.AppsEndUserLicenseAgreementGetToOneRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppsEndUserLicenseAgreementGetToOneRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsEndUserLicenseAgreements** | **[]string** | the fields to include for returned resources of type endUserLicenseAgreements | 

### Return type

[**EndUserLicenseAgreementResponse**](EndUserLicenseAgreementResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppsGameCenterEnabledVersionsGetToManyRelated

> GameCenterEnabledVersionsResponse AppsGameCenterEnabledVersionsGetToManyRelated(ctx, id).FilterPlatform(filterPlatform).FilterVersionString(filterVersionString).FilterId(filterId).Sort(sort).FieldsGameCenterEnabledVersions(fieldsGameCenterEnabledVersions).FieldsApps(fieldsApps).Limit(limit).LimitCompatibleVersions(limitCompatibleVersions).Include(include).Execute()



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
    filterPlatform := []string{"FilterPlatform_example"} // []string | filter by attribute 'platform' (optional)
    filterVersionString := []string{"Inner_example"} // []string | filter by attribute 'versionString' (optional)
    filterId := []string{"Inner_example"} // []string | filter by id(s) (optional)
    sort := []string{"Sort_example"} // []string | comma-separated list of sort expressions; resources will be sorted as specified (optional)
    fieldsGameCenterEnabledVersions := []string{"FieldsGameCenterEnabledVersions_example"} // []string | the fields to include for returned resources of type gameCenterEnabledVersions (optional)
    fieldsApps := []string{"FieldsApps_example"} // []string | the fields to include for returned resources of type apps (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    limitCompatibleVersions := int32(56) // int32 | maximum number of related compatibleVersions returned (when they are included) (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppsApi.AppsGameCenterEnabledVersionsGetToManyRelated(context.Background(), id).FilterPlatform(filterPlatform).FilterVersionString(filterVersionString).FilterId(filterId).Sort(sort).FieldsGameCenterEnabledVersions(fieldsGameCenterEnabledVersions).FieldsApps(fieldsApps).Limit(limit).LimitCompatibleVersions(limitCompatibleVersions).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppsApi.AppsGameCenterEnabledVersionsGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppsGameCenterEnabledVersionsGetToManyRelated`: GameCenterEnabledVersionsResponse
    fmt.Fprintf(os.Stdout, "Response from `AppsApi.AppsGameCenterEnabledVersionsGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppsGameCenterEnabledVersionsGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **filterPlatform** | **[]string** | filter by attribute &#39;platform&#39; | 
 **filterVersionString** | **[]string** | filter by attribute &#39;versionString&#39; | 
 **filterId** | **[]string** | filter by id(s) | 
 **sort** | **[]string** | comma-separated list of sort expressions; resources will be sorted as specified | 
 **fieldsGameCenterEnabledVersions** | **[]string** | the fields to include for returned resources of type gameCenterEnabledVersions | 
 **fieldsApps** | **[]string** | the fields to include for returned resources of type apps | 
 **limit** | **int32** | maximum resources per page | 
 **limitCompatibleVersions** | **int32** | maximum number of related compatibleVersions returned (when they are included) | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**GameCenterEnabledVersionsResponse**](GameCenterEnabledVersionsResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppsGetCollection

> AppsResponse AppsGetCollection(ctx).FilterAppStoreVersionsAppStoreState(filterAppStoreVersionsAppStoreState).FilterAppStoreVersionsPlatform(filterAppStoreVersionsPlatform).FilterBundleId(filterBundleId).FilterName(filterName).FilterSku(filterSku).FilterAppStoreVersions(filterAppStoreVersions).FilterId(filterId).ExistsGameCenterEnabledVersions(existsGameCenterEnabledVersions).Sort(sort).FieldsApps(fieldsApps).Limit(limit).Include(include).FieldsBetaAppReviewDetails(fieldsBetaAppReviewDetails).FieldsAppPriceSchedules(fieldsAppPriceSchedules).FieldsCiProducts(fieldsCiProducts).FieldsReviewSubmissions(fieldsReviewSubmissions).FieldsBetaGroups(fieldsBetaGroups).FieldsPromotedPurchases(fieldsPromotedPurchases).FieldsAppAvailabilities(fieldsAppAvailabilities).FieldsCustomerReviews(fieldsCustomerReviews).FieldsAppEvents(fieldsAppEvents).FieldsBuilds(fieldsBuilds).FieldsBetaLicenseAgreements(fieldsBetaLicenseAgreements).FieldsAppClips(fieldsAppClips).FieldsAppInfos(fieldsAppInfos).FieldsBetaAppLocalizations(fieldsBetaAppLocalizations).FieldsAppPricePoints(fieldsAppPricePoints).FieldsAppPricePoints2(fieldsAppPricePoints2).FieldsInAppPurchases(fieldsInAppPurchases).FieldsPreReleaseVersions(fieldsPreReleaseVersions).FieldsInAppPurchases2(fieldsInAppPurchases2).FieldsSubscriptionGroups(fieldsSubscriptionGroups).FieldsAppPrices(fieldsAppPrices).FieldsAppPreOrders(fieldsAppPreOrders).FieldsGameCenterEnabledVersions(fieldsGameCenterEnabledVersions).FieldsSubscriptionGracePeriods(fieldsSubscriptionGracePeriods).FieldsEndUserLicenseAgreements(fieldsEndUserLicenseAgreements).FieldsAppStoreVersions(fieldsAppStoreVersions).FieldsAppCustomProductPages(fieldsAppCustomProductPages).FieldsTerritories(fieldsTerritories).FieldsPerfPowerMetrics(fieldsPerfPowerMetrics).LimitAppClips(limitAppClips).LimitAppCustomProductPages(limitAppCustomProductPages).LimitAppEvents(limitAppEvents).LimitAppInfos(limitAppInfos).LimitAppStoreVersions(limitAppStoreVersions).LimitAvailableTerritories(limitAvailableTerritories).LimitBetaAppLocalizations(limitBetaAppLocalizations).LimitBetaGroups(limitBetaGroups).LimitBuilds(limitBuilds).LimitGameCenterEnabledVersions(limitGameCenterEnabledVersions).LimitInAppPurchases(limitInAppPurchases).LimitInAppPurchasesV2(limitInAppPurchasesV2).LimitPreReleaseVersions(limitPreReleaseVersions).LimitPrices(limitPrices).LimitPromotedPurchases(limitPromotedPurchases).LimitReviewSubmissions(limitReviewSubmissions).LimitSubscriptionGroups(limitSubscriptionGroups).Execute()



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
    filterAppStoreVersionsAppStoreState := []string{"FilterAppStoreVersionsAppStoreState_example"} // []string | filter by attribute 'appStoreVersions.appStoreState' (optional)
    filterAppStoreVersionsPlatform := []string{"FilterAppStoreVersionsPlatform_example"} // []string | filter by attribute 'appStoreVersions.platform' (optional)
    filterBundleId := []string{"Inner_example"} // []string | filter by attribute 'bundleId' (optional)
    filterName := []string{"Inner_example"} // []string | filter by attribute 'name' (optional)
    filterSku := []string{"Inner_example"} // []string | filter by attribute 'sku' (optional)
    filterAppStoreVersions := []string{"Inner_example"} // []string | filter by id(s) of related 'appStoreVersions' (optional)
    filterId := []string{"Inner_example"} // []string | filter by id(s) (optional)
    existsGameCenterEnabledVersions := true // bool | filter by existence or non-existence of related 'gameCenterEnabledVersions' (optional)
    sort := []string{"Sort_example"} // []string | comma-separated list of sort expressions; resources will be sorted as specified (optional)
    fieldsApps := []string{"FieldsApps_example"} // []string | the fields to include for returned resources of type apps (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)
    fieldsBetaAppReviewDetails := []string{"FieldsBetaAppReviewDetails_example"} // []string | the fields to include for returned resources of type betaAppReviewDetails (optional)
    fieldsAppPriceSchedules := []string{"FieldsAppPriceSchedules_example"} // []string | the fields to include for returned resources of type appPriceSchedules (optional)
    fieldsCiProducts := []string{"FieldsCiProducts_example"} // []string | the fields to include for returned resources of type ciProducts (optional)
    fieldsReviewSubmissions := []string{"FieldsReviewSubmissions_example"} // []string | the fields to include for returned resources of type reviewSubmissions (optional)
    fieldsBetaGroups := []string{"FieldsBetaGroups_example"} // []string | the fields to include for returned resources of type betaGroups (optional)
    fieldsPromotedPurchases := []string{"FieldsPromotedPurchases_example"} // []string | the fields to include for returned resources of type promotedPurchases (optional)
    fieldsAppAvailabilities := []string{"FieldsAppAvailabilities_example"} // []string | the fields to include for returned resources of type appAvailabilities (optional)
    fieldsCustomerReviews := []string{"FieldsCustomerReviews_example"} // []string | the fields to include for returned resources of type customerReviews (optional)
    fieldsAppEvents := []string{"FieldsAppEvents_example"} // []string | the fields to include for returned resources of type appEvents (optional)
    fieldsBuilds := []string{"FieldsBuilds_example"} // []string | the fields to include for returned resources of type builds (optional)
    fieldsBetaLicenseAgreements := []string{"FieldsBetaLicenseAgreements_example"} // []string | the fields to include for returned resources of type betaLicenseAgreements (optional)
    fieldsAppClips := []string{"FieldsAppClips_example"} // []string | the fields to include for returned resources of type appClips (optional)
    fieldsAppInfos := []string{"FieldsAppInfos_example"} // []string | the fields to include for returned resources of type appInfos (optional)
    fieldsBetaAppLocalizations := []string{"FieldsBetaAppLocalizations_example"} // []string | the fields to include for returned resources of type betaAppLocalizations (optional)
    fieldsAppPricePoints := []string{"FieldsAppPricePoints_example"} // []string | the fields to include for returned resources of type appPricePoints (optional)
    fieldsAppPricePoints2 := []string{"FieldsAppPricePoints_example"} // []string | the fields to include for returned resources of type appPricePoints (optional)
    fieldsInAppPurchases := []string{"FieldsInAppPurchases_example"} // []string | the fields to include for returned resources of type inAppPurchases (optional)
    fieldsPreReleaseVersions := []string{"FieldsPreReleaseVersions_example"} // []string | the fields to include for returned resources of type preReleaseVersions (optional)
    fieldsInAppPurchases2 := []string{"FieldsInAppPurchases_example"} // []string | the fields to include for returned resources of type inAppPurchases (optional)
    fieldsSubscriptionGroups := []string{"FieldsSubscriptionGroups_example"} // []string | the fields to include for returned resources of type subscriptionGroups (optional)
    fieldsAppPrices := []string{"FieldsAppPrices_example"} // []string | the fields to include for returned resources of type appPrices (optional)
    fieldsAppPreOrders := []string{"FieldsAppPreOrders_example"} // []string | the fields to include for returned resources of type appPreOrders (optional)
    fieldsGameCenterEnabledVersions := []string{"FieldsGameCenterEnabledVersions_example"} // []string | the fields to include for returned resources of type gameCenterEnabledVersions (optional)
    fieldsSubscriptionGracePeriods := []string{"FieldsSubscriptionGracePeriods_example"} // []string | the fields to include for returned resources of type subscriptionGracePeriods (optional)
    fieldsEndUserLicenseAgreements := []string{"FieldsEndUserLicenseAgreements_example"} // []string | the fields to include for returned resources of type endUserLicenseAgreements (optional)
    fieldsAppStoreVersions := []string{"FieldsAppStoreVersions_example"} // []string | the fields to include for returned resources of type appStoreVersions (optional)
    fieldsAppCustomProductPages := []string{"FieldsAppCustomProductPages_example"} // []string | the fields to include for returned resources of type appCustomProductPages (optional)
    fieldsTerritories := []string{"FieldsTerritories_example"} // []string | the fields to include for returned resources of type territories (optional)
    fieldsPerfPowerMetrics := []string{"FieldsPerfPowerMetrics_example"} // []string | the fields to include for returned resources of type perfPowerMetrics (optional)
    limitAppClips := int32(56) // int32 | maximum number of related appClips returned (when they are included) (optional)
    limitAppCustomProductPages := int32(56) // int32 | maximum number of related appCustomProductPages returned (when they are included) (optional)
    limitAppEvents := int32(56) // int32 | maximum number of related appEvents returned (when they are included) (optional)
    limitAppInfos := int32(56) // int32 | maximum number of related appInfos returned (when they are included) (optional)
    limitAppStoreVersions := int32(56) // int32 | maximum number of related appStoreVersions returned (when they are included) (optional)
    limitAvailableTerritories := int32(56) // int32 | maximum number of related availableTerritories returned (when they are included) (optional)
    limitBetaAppLocalizations := int32(56) // int32 | maximum number of related betaAppLocalizations returned (when they are included) (optional)
    limitBetaGroups := int32(56) // int32 | maximum number of related betaGroups returned (when they are included) (optional)
    limitBuilds := int32(56) // int32 | maximum number of related builds returned (when they are included) (optional)
    limitGameCenterEnabledVersions := int32(56) // int32 | maximum number of related gameCenterEnabledVersions returned (when they are included) (optional)
    limitInAppPurchases := int32(56) // int32 | maximum number of related inAppPurchases returned (when they are included) (optional)
    limitInAppPurchasesV2 := int32(56) // int32 | maximum number of related inAppPurchasesV2 returned (when they are included) (optional)
    limitPreReleaseVersions := int32(56) // int32 | maximum number of related preReleaseVersions returned (when they are included) (optional)
    limitPrices := int32(56) // int32 | maximum number of related prices returned (when they are included) (optional)
    limitPromotedPurchases := int32(56) // int32 | maximum number of related promotedPurchases returned (when they are included) (optional)
    limitReviewSubmissions := int32(56) // int32 | maximum number of related reviewSubmissions returned (when they are included) (optional)
    limitSubscriptionGroups := int32(56) // int32 | maximum number of related subscriptionGroups returned (when they are included) (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppsApi.AppsGetCollection(context.Background()).FilterAppStoreVersionsAppStoreState(filterAppStoreVersionsAppStoreState).FilterAppStoreVersionsPlatform(filterAppStoreVersionsPlatform).FilterBundleId(filterBundleId).FilterName(filterName).FilterSku(filterSku).FilterAppStoreVersions(filterAppStoreVersions).FilterId(filterId).ExistsGameCenterEnabledVersions(existsGameCenterEnabledVersions).Sort(sort).FieldsApps(fieldsApps).Limit(limit).Include(include).FieldsBetaAppReviewDetails(fieldsBetaAppReviewDetails).FieldsAppPriceSchedules(fieldsAppPriceSchedules).FieldsCiProducts(fieldsCiProducts).FieldsReviewSubmissions(fieldsReviewSubmissions).FieldsBetaGroups(fieldsBetaGroups).FieldsPromotedPurchases(fieldsPromotedPurchases).FieldsAppAvailabilities(fieldsAppAvailabilities).FieldsCustomerReviews(fieldsCustomerReviews).FieldsAppEvents(fieldsAppEvents).FieldsBuilds(fieldsBuilds).FieldsBetaLicenseAgreements(fieldsBetaLicenseAgreements).FieldsAppClips(fieldsAppClips).FieldsAppInfos(fieldsAppInfos).FieldsBetaAppLocalizations(fieldsBetaAppLocalizations).FieldsAppPricePoints(fieldsAppPricePoints).FieldsAppPricePoints2(fieldsAppPricePoints2).FieldsInAppPurchases(fieldsInAppPurchases).FieldsPreReleaseVersions(fieldsPreReleaseVersions).FieldsInAppPurchases2(fieldsInAppPurchases2).FieldsSubscriptionGroups(fieldsSubscriptionGroups).FieldsAppPrices(fieldsAppPrices).FieldsAppPreOrders(fieldsAppPreOrders).FieldsGameCenterEnabledVersions(fieldsGameCenterEnabledVersions).FieldsSubscriptionGracePeriods(fieldsSubscriptionGracePeriods).FieldsEndUserLicenseAgreements(fieldsEndUserLicenseAgreements).FieldsAppStoreVersions(fieldsAppStoreVersions).FieldsAppCustomProductPages(fieldsAppCustomProductPages).FieldsTerritories(fieldsTerritories).FieldsPerfPowerMetrics(fieldsPerfPowerMetrics).LimitAppClips(limitAppClips).LimitAppCustomProductPages(limitAppCustomProductPages).LimitAppEvents(limitAppEvents).LimitAppInfos(limitAppInfos).LimitAppStoreVersions(limitAppStoreVersions).LimitAvailableTerritories(limitAvailableTerritories).LimitBetaAppLocalizations(limitBetaAppLocalizations).LimitBetaGroups(limitBetaGroups).LimitBuilds(limitBuilds).LimitGameCenterEnabledVersions(limitGameCenterEnabledVersions).LimitInAppPurchases(limitInAppPurchases).LimitInAppPurchasesV2(limitInAppPurchasesV2).LimitPreReleaseVersions(limitPreReleaseVersions).LimitPrices(limitPrices).LimitPromotedPurchases(limitPromotedPurchases).LimitReviewSubmissions(limitReviewSubmissions).LimitSubscriptionGroups(limitSubscriptionGroups).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppsApi.AppsGetCollection``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppsGetCollection`: AppsResponse
    fmt.Fprintf(os.Stdout, "Response from `AppsApi.AppsGetCollection`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiAppsGetCollectionRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **filterAppStoreVersionsAppStoreState** | **[]string** | filter by attribute &#39;appStoreVersions.appStoreState&#39; | 
 **filterAppStoreVersionsPlatform** | **[]string** | filter by attribute &#39;appStoreVersions.platform&#39; | 
 **filterBundleId** | **[]string** | filter by attribute &#39;bundleId&#39; | 
 **filterName** | **[]string** | filter by attribute &#39;name&#39; | 
 **filterSku** | **[]string** | filter by attribute &#39;sku&#39; | 
 **filterAppStoreVersions** | **[]string** | filter by id(s) of related &#39;appStoreVersions&#39; | 
 **filterId** | **[]string** | filter by id(s) | 
 **existsGameCenterEnabledVersions** | **bool** | filter by existence or non-existence of related &#39;gameCenterEnabledVersions&#39; | 
 **sort** | **[]string** | comma-separated list of sort expressions; resources will be sorted as specified | 
 **fieldsApps** | **[]string** | the fields to include for returned resources of type apps | 
 **limit** | **int32** | maximum resources per page | 
 **include** | **[]string** | comma-separated list of relationships to include | 
 **fieldsBetaAppReviewDetails** | **[]string** | the fields to include for returned resources of type betaAppReviewDetails | 
 **fieldsAppPriceSchedules** | **[]string** | the fields to include for returned resources of type appPriceSchedules | 
 **fieldsCiProducts** | **[]string** | the fields to include for returned resources of type ciProducts | 
 **fieldsReviewSubmissions** | **[]string** | the fields to include for returned resources of type reviewSubmissions | 
 **fieldsBetaGroups** | **[]string** | the fields to include for returned resources of type betaGroups | 
 **fieldsPromotedPurchases** | **[]string** | the fields to include for returned resources of type promotedPurchases | 
 **fieldsAppAvailabilities** | **[]string** | the fields to include for returned resources of type appAvailabilities | 
 **fieldsCustomerReviews** | **[]string** | the fields to include for returned resources of type customerReviews | 
 **fieldsAppEvents** | **[]string** | the fields to include for returned resources of type appEvents | 
 **fieldsBuilds** | **[]string** | the fields to include for returned resources of type builds | 
 **fieldsBetaLicenseAgreements** | **[]string** | the fields to include for returned resources of type betaLicenseAgreements | 
 **fieldsAppClips** | **[]string** | the fields to include for returned resources of type appClips | 
 **fieldsAppInfos** | **[]string** | the fields to include for returned resources of type appInfos | 
 **fieldsBetaAppLocalizations** | **[]string** | the fields to include for returned resources of type betaAppLocalizations | 
 **fieldsAppPricePoints** | **[]string** | the fields to include for returned resources of type appPricePoints | 
 **fieldsAppPricePoints2** | **[]string** | the fields to include for returned resources of type appPricePoints | 
 **fieldsInAppPurchases** | **[]string** | the fields to include for returned resources of type inAppPurchases | 
 **fieldsPreReleaseVersions** | **[]string** | the fields to include for returned resources of type preReleaseVersions | 
 **fieldsInAppPurchases2** | **[]string** | the fields to include for returned resources of type inAppPurchases | 
 **fieldsSubscriptionGroups** | **[]string** | the fields to include for returned resources of type subscriptionGroups | 
 **fieldsAppPrices** | **[]string** | the fields to include for returned resources of type appPrices | 
 **fieldsAppPreOrders** | **[]string** | the fields to include for returned resources of type appPreOrders | 
 **fieldsGameCenterEnabledVersions** | **[]string** | the fields to include for returned resources of type gameCenterEnabledVersions | 
 **fieldsSubscriptionGracePeriods** | **[]string** | the fields to include for returned resources of type subscriptionGracePeriods | 
 **fieldsEndUserLicenseAgreements** | **[]string** | the fields to include for returned resources of type endUserLicenseAgreements | 
 **fieldsAppStoreVersions** | **[]string** | the fields to include for returned resources of type appStoreVersions | 
 **fieldsAppCustomProductPages** | **[]string** | the fields to include for returned resources of type appCustomProductPages | 
 **fieldsTerritories** | **[]string** | the fields to include for returned resources of type territories | 
 **fieldsPerfPowerMetrics** | **[]string** | the fields to include for returned resources of type perfPowerMetrics | 
 **limitAppClips** | **int32** | maximum number of related appClips returned (when they are included) | 
 **limitAppCustomProductPages** | **int32** | maximum number of related appCustomProductPages returned (when they are included) | 
 **limitAppEvents** | **int32** | maximum number of related appEvents returned (when they are included) | 
 **limitAppInfos** | **int32** | maximum number of related appInfos returned (when they are included) | 
 **limitAppStoreVersions** | **int32** | maximum number of related appStoreVersions returned (when they are included) | 
 **limitAvailableTerritories** | **int32** | maximum number of related availableTerritories returned (when they are included) | 
 **limitBetaAppLocalizations** | **int32** | maximum number of related betaAppLocalizations returned (when they are included) | 
 **limitBetaGroups** | **int32** | maximum number of related betaGroups returned (when they are included) | 
 **limitBuilds** | **int32** | maximum number of related builds returned (when they are included) | 
 **limitGameCenterEnabledVersions** | **int32** | maximum number of related gameCenterEnabledVersions returned (when they are included) | 
 **limitInAppPurchases** | **int32** | maximum number of related inAppPurchases returned (when they are included) | 
 **limitInAppPurchasesV2** | **int32** | maximum number of related inAppPurchasesV2 returned (when they are included) | 
 **limitPreReleaseVersions** | **int32** | maximum number of related preReleaseVersions returned (when they are included) | 
 **limitPrices** | **int32** | maximum number of related prices returned (when they are included) | 
 **limitPromotedPurchases** | **int32** | maximum number of related promotedPurchases returned (when they are included) | 
 **limitReviewSubmissions** | **int32** | maximum number of related reviewSubmissions returned (when they are included) | 
 **limitSubscriptionGroups** | **int32** | maximum number of related subscriptionGroups returned (when they are included) | 

### Return type

[**AppsResponse**](AppsResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppsGetInstance

> AppResponse AppsGetInstance(ctx, id).FieldsApps(fieldsApps).Include(include).FieldsBetaAppReviewDetails(fieldsBetaAppReviewDetails).FieldsAppPriceSchedules(fieldsAppPriceSchedules).FieldsCiProducts(fieldsCiProducts).FieldsReviewSubmissions(fieldsReviewSubmissions).FieldsBetaGroups(fieldsBetaGroups).FieldsPromotedPurchases(fieldsPromotedPurchases).FieldsAppAvailabilities(fieldsAppAvailabilities).FieldsCustomerReviews(fieldsCustomerReviews).FieldsAppEvents(fieldsAppEvents).FieldsBuilds(fieldsBuilds).FieldsBetaLicenseAgreements(fieldsBetaLicenseAgreements).FieldsAppClips(fieldsAppClips).FieldsAppInfos(fieldsAppInfos).FieldsBetaAppLocalizations(fieldsBetaAppLocalizations).FieldsAppPricePoints(fieldsAppPricePoints).FieldsAppPricePoints2(fieldsAppPricePoints2).FieldsInAppPurchases(fieldsInAppPurchases).FieldsPreReleaseVersions(fieldsPreReleaseVersions).FieldsInAppPurchases2(fieldsInAppPurchases2).FieldsSubscriptionGroups(fieldsSubscriptionGroups).FieldsAppPrices(fieldsAppPrices).FieldsAppPreOrders(fieldsAppPreOrders).FieldsGameCenterEnabledVersions(fieldsGameCenterEnabledVersions).FieldsSubscriptionGracePeriods(fieldsSubscriptionGracePeriods).FieldsEndUserLicenseAgreements(fieldsEndUserLicenseAgreements).FieldsAppStoreVersions(fieldsAppStoreVersions).FieldsAppCustomProductPages(fieldsAppCustomProductPages).FieldsTerritories(fieldsTerritories).FieldsPerfPowerMetrics(fieldsPerfPowerMetrics).LimitAppClips(limitAppClips).LimitAppCustomProductPages(limitAppCustomProductPages).LimitAppEvents(limitAppEvents).LimitAppInfos(limitAppInfos).LimitAppStoreVersions(limitAppStoreVersions).LimitAvailableTerritories(limitAvailableTerritories).LimitBetaAppLocalizations(limitBetaAppLocalizations).LimitBetaGroups(limitBetaGroups).LimitBuilds(limitBuilds).LimitGameCenterEnabledVersions(limitGameCenterEnabledVersions).LimitInAppPurchases(limitInAppPurchases).LimitInAppPurchasesV2(limitInAppPurchasesV2).LimitPreReleaseVersions(limitPreReleaseVersions).LimitPrices(limitPrices).LimitPromotedPurchases(limitPromotedPurchases).LimitReviewSubmissions(limitReviewSubmissions).LimitSubscriptionGroups(limitSubscriptionGroups).Execute()



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
    fieldsApps := []string{"FieldsApps_example"} // []string | the fields to include for returned resources of type apps (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)
    fieldsBetaAppReviewDetails := []string{"FieldsBetaAppReviewDetails_example"} // []string | the fields to include for returned resources of type betaAppReviewDetails (optional)
    fieldsAppPriceSchedules := []string{"FieldsAppPriceSchedules_example"} // []string | the fields to include for returned resources of type appPriceSchedules (optional)
    fieldsCiProducts := []string{"FieldsCiProducts_example"} // []string | the fields to include for returned resources of type ciProducts (optional)
    fieldsReviewSubmissions := []string{"FieldsReviewSubmissions_example"} // []string | the fields to include for returned resources of type reviewSubmissions (optional)
    fieldsBetaGroups := []string{"FieldsBetaGroups_example"} // []string | the fields to include for returned resources of type betaGroups (optional)
    fieldsPromotedPurchases := []string{"FieldsPromotedPurchases_example"} // []string | the fields to include for returned resources of type promotedPurchases (optional)
    fieldsAppAvailabilities := []string{"FieldsAppAvailabilities_example"} // []string | the fields to include for returned resources of type appAvailabilities (optional)
    fieldsCustomerReviews := []string{"FieldsCustomerReviews_example"} // []string | the fields to include for returned resources of type customerReviews (optional)
    fieldsAppEvents := []string{"FieldsAppEvents_example"} // []string | the fields to include for returned resources of type appEvents (optional)
    fieldsBuilds := []string{"FieldsBuilds_example"} // []string | the fields to include for returned resources of type builds (optional)
    fieldsBetaLicenseAgreements := []string{"FieldsBetaLicenseAgreements_example"} // []string | the fields to include for returned resources of type betaLicenseAgreements (optional)
    fieldsAppClips := []string{"FieldsAppClips_example"} // []string | the fields to include for returned resources of type appClips (optional)
    fieldsAppInfos := []string{"FieldsAppInfos_example"} // []string | the fields to include for returned resources of type appInfos (optional)
    fieldsBetaAppLocalizations := []string{"FieldsBetaAppLocalizations_example"} // []string | the fields to include for returned resources of type betaAppLocalizations (optional)
    fieldsAppPricePoints := []string{"FieldsAppPricePoints_example"} // []string | the fields to include for returned resources of type appPricePoints (optional)
    fieldsAppPricePoints2 := []string{"FieldsAppPricePoints_example"} // []string | the fields to include for returned resources of type appPricePoints (optional)
    fieldsInAppPurchases := []string{"FieldsInAppPurchases_example"} // []string | the fields to include for returned resources of type inAppPurchases (optional)
    fieldsPreReleaseVersions := []string{"FieldsPreReleaseVersions_example"} // []string | the fields to include for returned resources of type preReleaseVersions (optional)
    fieldsInAppPurchases2 := []string{"FieldsInAppPurchases_example"} // []string | the fields to include for returned resources of type inAppPurchases (optional)
    fieldsSubscriptionGroups := []string{"FieldsSubscriptionGroups_example"} // []string | the fields to include for returned resources of type subscriptionGroups (optional)
    fieldsAppPrices := []string{"FieldsAppPrices_example"} // []string | the fields to include for returned resources of type appPrices (optional)
    fieldsAppPreOrders := []string{"FieldsAppPreOrders_example"} // []string | the fields to include for returned resources of type appPreOrders (optional)
    fieldsGameCenterEnabledVersions := []string{"FieldsGameCenterEnabledVersions_example"} // []string | the fields to include for returned resources of type gameCenterEnabledVersions (optional)
    fieldsSubscriptionGracePeriods := []string{"FieldsSubscriptionGracePeriods_example"} // []string | the fields to include for returned resources of type subscriptionGracePeriods (optional)
    fieldsEndUserLicenseAgreements := []string{"FieldsEndUserLicenseAgreements_example"} // []string | the fields to include for returned resources of type endUserLicenseAgreements (optional)
    fieldsAppStoreVersions := []string{"FieldsAppStoreVersions_example"} // []string | the fields to include for returned resources of type appStoreVersions (optional)
    fieldsAppCustomProductPages := []string{"FieldsAppCustomProductPages_example"} // []string | the fields to include for returned resources of type appCustomProductPages (optional)
    fieldsTerritories := []string{"FieldsTerritories_example"} // []string | the fields to include for returned resources of type territories (optional)
    fieldsPerfPowerMetrics := []string{"FieldsPerfPowerMetrics_example"} // []string | the fields to include for returned resources of type perfPowerMetrics (optional)
    limitAppClips := int32(56) // int32 | maximum number of related appClips returned (when they are included) (optional)
    limitAppCustomProductPages := int32(56) // int32 | maximum number of related appCustomProductPages returned (when they are included) (optional)
    limitAppEvents := int32(56) // int32 | maximum number of related appEvents returned (when they are included) (optional)
    limitAppInfos := int32(56) // int32 | maximum number of related appInfos returned (when they are included) (optional)
    limitAppStoreVersions := int32(56) // int32 | maximum number of related appStoreVersions returned (when they are included) (optional)
    limitAvailableTerritories := int32(56) // int32 | maximum number of related availableTerritories returned (when they are included) (optional)
    limitBetaAppLocalizations := int32(56) // int32 | maximum number of related betaAppLocalizations returned (when they are included) (optional)
    limitBetaGroups := int32(56) // int32 | maximum number of related betaGroups returned (when they are included) (optional)
    limitBuilds := int32(56) // int32 | maximum number of related builds returned (when they are included) (optional)
    limitGameCenterEnabledVersions := int32(56) // int32 | maximum number of related gameCenterEnabledVersions returned (when they are included) (optional)
    limitInAppPurchases := int32(56) // int32 | maximum number of related inAppPurchases returned (when they are included) (optional)
    limitInAppPurchasesV2 := int32(56) // int32 | maximum number of related inAppPurchasesV2 returned (when they are included) (optional)
    limitPreReleaseVersions := int32(56) // int32 | maximum number of related preReleaseVersions returned (when they are included) (optional)
    limitPrices := int32(56) // int32 | maximum number of related prices returned (when they are included) (optional)
    limitPromotedPurchases := int32(56) // int32 | maximum number of related promotedPurchases returned (when they are included) (optional)
    limitReviewSubmissions := int32(56) // int32 | maximum number of related reviewSubmissions returned (when they are included) (optional)
    limitSubscriptionGroups := int32(56) // int32 | maximum number of related subscriptionGroups returned (when they are included) (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppsApi.AppsGetInstance(context.Background(), id).FieldsApps(fieldsApps).Include(include).FieldsBetaAppReviewDetails(fieldsBetaAppReviewDetails).FieldsAppPriceSchedules(fieldsAppPriceSchedules).FieldsCiProducts(fieldsCiProducts).FieldsReviewSubmissions(fieldsReviewSubmissions).FieldsBetaGroups(fieldsBetaGroups).FieldsPromotedPurchases(fieldsPromotedPurchases).FieldsAppAvailabilities(fieldsAppAvailabilities).FieldsCustomerReviews(fieldsCustomerReviews).FieldsAppEvents(fieldsAppEvents).FieldsBuilds(fieldsBuilds).FieldsBetaLicenseAgreements(fieldsBetaLicenseAgreements).FieldsAppClips(fieldsAppClips).FieldsAppInfos(fieldsAppInfos).FieldsBetaAppLocalizations(fieldsBetaAppLocalizations).FieldsAppPricePoints(fieldsAppPricePoints).FieldsAppPricePoints2(fieldsAppPricePoints2).FieldsInAppPurchases(fieldsInAppPurchases).FieldsPreReleaseVersions(fieldsPreReleaseVersions).FieldsInAppPurchases2(fieldsInAppPurchases2).FieldsSubscriptionGroups(fieldsSubscriptionGroups).FieldsAppPrices(fieldsAppPrices).FieldsAppPreOrders(fieldsAppPreOrders).FieldsGameCenterEnabledVersions(fieldsGameCenterEnabledVersions).FieldsSubscriptionGracePeriods(fieldsSubscriptionGracePeriods).FieldsEndUserLicenseAgreements(fieldsEndUserLicenseAgreements).FieldsAppStoreVersions(fieldsAppStoreVersions).FieldsAppCustomProductPages(fieldsAppCustomProductPages).FieldsTerritories(fieldsTerritories).FieldsPerfPowerMetrics(fieldsPerfPowerMetrics).LimitAppClips(limitAppClips).LimitAppCustomProductPages(limitAppCustomProductPages).LimitAppEvents(limitAppEvents).LimitAppInfos(limitAppInfos).LimitAppStoreVersions(limitAppStoreVersions).LimitAvailableTerritories(limitAvailableTerritories).LimitBetaAppLocalizations(limitBetaAppLocalizations).LimitBetaGroups(limitBetaGroups).LimitBuilds(limitBuilds).LimitGameCenterEnabledVersions(limitGameCenterEnabledVersions).LimitInAppPurchases(limitInAppPurchases).LimitInAppPurchasesV2(limitInAppPurchasesV2).LimitPreReleaseVersions(limitPreReleaseVersions).LimitPrices(limitPrices).LimitPromotedPurchases(limitPromotedPurchases).LimitReviewSubmissions(limitReviewSubmissions).LimitSubscriptionGroups(limitSubscriptionGroups).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppsApi.AppsGetInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppsGetInstance`: AppResponse
    fmt.Fprintf(os.Stdout, "Response from `AppsApi.AppsGetInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppsGetInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsApps** | **[]string** | the fields to include for returned resources of type apps | 
 **include** | **[]string** | comma-separated list of relationships to include | 
 **fieldsBetaAppReviewDetails** | **[]string** | the fields to include for returned resources of type betaAppReviewDetails | 
 **fieldsAppPriceSchedules** | **[]string** | the fields to include for returned resources of type appPriceSchedules | 
 **fieldsCiProducts** | **[]string** | the fields to include for returned resources of type ciProducts | 
 **fieldsReviewSubmissions** | **[]string** | the fields to include for returned resources of type reviewSubmissions | 
 **fieldsBetaGroups** | **[]string** | the fields to include for returned resources of type betaGroups | 
 **fieldsPromotedPurchases** | **[]string** | the fields to include for returned resources of type promotedPurchases | 
 **fieldsAppAvailabilities** | **[]string** | the fields to include for returned resources of type appAvailabilities | 
 **fieldsCustomerReviews** | **[]string** | the fields to include for returned resources of type customerReviews | 
 **fieldsAppEvents** | **[]string** | the fields to include for returned resources of type appEvents | 
 **fieldsBuilds** | **[]string** | the fields to include for returned resources of type builds | 
 **fieldsBetaLicenseAgreements** | **[]string** | the fields to include for returned resources of type betaLicenseAgreements | 
 **fieldsAppClips** | **[]string** | the fields to include for returned resources of type appClips | 
 **fieldsAppInfos** | **[]string** | the fields to include for returned resources of type appInfos | 
 **fieldsBetaAppLocalizations** | **[]string** | the fields to include for returned resources of type betaAppLocalizations | 
 **fieldsAppPricePoints** | **[]string** | the fields to include for returned resources of type appPricePoints | 
 **fieldsAppPricePoints2** | **[]string** | the fields to include for returned resources of type appPricePoints | 
 **fieldsInAppPurchases** | **[]string** | the fields to include for returned resources of type inAppPurchases | 
 **fieldsPreReleaseVersions** | **[]string** | the fields to include for returned resources of type preReleaseVersions | 
 **fieldsInAppPurchases2** | **[]string** | the fields to include for returned resources of type inAppPurchases | 
 **fieldsSubscriptionGroups** | **[]string** | the fields to include for returned resources of type subscriptionGroups | 
 **fieldsAppPrices** | **[]string** | the fields to include for returned resources of type appPrices | 
 **fieldsAppPreOrders** | **[]string** | the fields to include for returned resources of type appPreOrders | 
 **fieldsGameCenterEnabledVersions** | **[]string** | the fields to include for returned resources of type gameCenterEnabledVersions | 
 **fieldsSubscriptionGracePeriods** | **[]string** | the fields to include for returned resources of type subscriptionGracePeriods | 
 **fieldsEndUserLicenseAgreements** | **[]string** | the fields to include for returned resources of type endUserLicenseAgreements | 
 **fieldsAppStoreVersions** | **[]string** | the fields to include for returned resources of type appStoreVersions | 
 **fieldsAppCustomProductPages** | **[]string** | the fields to include for returned resources of type appCustomProductPages | 
 **fieldsTerritories** | **[]string** | the fields to include for returned resources of type territories | 
 **fieldsPerfPowerMetrics** | **[]string** | the fields to include for returned resources of type perfPowerMetrics | 
 **limitAppClips** | **int32** | maximum number of related appClips returned (when they are included) | 
 **limitAppCustomProductPages** | **int32** | maximum number of related appCustomProductPages returned (when they are included) | 
 **limitAppEvents** | **int32** | maximum number of related appEvents returned (when they are included) | 
 **limitAppInfos** | **int32** | maximum number of related appInfos returned (when they are included) | 
 **limitAppStoreVersions** | **int32** | maximum number of related appStoreVersions returned (when they are included) | 
 **limitAvailableTerritories** | **int32** | maximum number of related availableTerritories returned (when they are included) | 
 **limitBetaAppLocalizations** | **int32** | maximum number of related betaAppLocalizations returned (when they are included) | 
 **limitBetaGroups** | **int32** | maximum number of related betaGroups returned (when they are included) | 
 **limitBuilds** | **int32** | maximum number of related builds returned (when they are included) | 
 **limitGameCenterEnabledVersions** | **int32** | maximum number of related gameCenterEnabledVersions returned (when they are included) | 
 **limitInAppPurchases** | **int32** | maximum number of related inAppPurchases returned (when they are included) | 
 **limitInAppPurchasesV2** | **int32** | maximum number of related inAppPurchasesV2 returned (when they are included) | 
 **limitPreReleaseVersions** | **int32** | maximum number of related preReleaseVersions returned (when they are included) | 
 **limitPrices** | **int32** | maximum number of related prices returned (when they are included) | 
 **limitPromotedPurchases** | **int32** | maximum number of related promotedPurchases returned (when they are included) | 
 **limitReviewSubmissions** | **int32** | maximum number of related reviewSubmissions returned (when they are included) | 
 **limitSubscriptionGroups** | **int32** | maximum number of related subscriptionGroups returned (when they are included) | 

### Return type

[**AppResponse**](AppResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppsInAppPurchasesGetToManyRelated

> InAppPurchasesResponse AppsInAppPurchasesGetToManyRelated(ctx, id).FilterInAppPurchaseType(filterInAppPurchaseType).FilterCanBeSubmitted(filterCanBeSubmitted).Sort(sort).FieldsInAppPurchases(fieldsInAppPurchases).FieldsApps(fieldsApps).Limit(limit).LimitApps(limitApps).Include(include).Execute()



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
    filterInAppPurchaseType := []string{"FilterInAppPurchaseType_example"} // []string | filter by attribute 'inAppPurchaseType' (optional)
    filterCanBeSubmitted := []string{"Inner_example"} // []string | filter by canBeSubmitted (optional)
    sort := []string{"Sort_example"} // []string | comma-separated list of sort expressions; resources will be sorted as specified (optional)
    fieldsInAppPurchases := []string{"FieldsInAppPurchases_example"} // []string | the fields to include for returned resources of type inAppPurchases (optional)
    fieldsApps := []string{"FieldsApps_example"} // []string | the fields to include for returned resources of type apps (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    limitApps := int32(56) // int32 | maximum number of related apps returned (when they are included) (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppsApi.AppsInAppPurchasesGetToManyRelated(context.Background(), id).FilterInAppPurchaseType(filterInAppPurchaseType).FilterCanBeSubmitted(filterCanBeSubmitted).Sort(sort).FieldsInAppPurchases(fieldsInAppPurchases).FieldsApps(fieldsApps).Limit(limit).LimitApps(limitApps).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppsApi.AppsInAppPurchasesGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppsInAppPurchasesGetToManyRelated`: InAppPurchasesResponse
    fmt.Fprintf(os.Stdout, "Response from `AppsApi.AppsInAppPurchasesGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppsInAppPurchasesGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **filterInAppPurchaseType** | **[]string** | filter by attribute &#39;inAppPurchaseType&#39; | 
 **filterCanBeSubmitted** | **[]string** | filter by canBeSubmitted | 
 **sort** | **[]string** | comma-separated list of sort expressions; resources will be sorted as specified | 
 **fieldsInAppPurchases** | **[]string** | the fields to include for returned resources of type inAppPurchases | 
 **fieldsApps** | **[]string** | the fields to include for returned resources of type apps | 
 **limit** | **int32** | maximum resources per page | 
 **limitApps** | **int32** | maximum number of related apps returned (when they are included) | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**InAppPurchasesResponse**](InAppPurchasesResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppsInAppPurchasesV2GetToManyRelated

> InAppPurchasesV2Response AppsInAppPurchasesV2GetToManyRelated(ctx, id).FilterInAppPurchaseType(filterInAppPurchaseType).FilterName(filterName).FilterProductId(filterProductId).FilterState(filterState).Sort(sort).FieldsInAppPurchaseAppStoreReviewScreenshots(fieldsInAppPurchaseAppStoreReviewScreenshots).FieldsInAppPurchasePricePoints(fieldsInAppPurchasePricePoints).FieldsPromotedPurchases(fieldsPromotedPurchases).FieldsInAppPurchaseLocalizations(fieldsInAppPurchaseLocalizations).FieldsInAppPurchases(fieldsInAppPurchases).FieldsInAppPurchasePriceSchedules(fieldsInAppPurchasePriceSchedules).FieldsInAppPurchaseContents(fieldsInAppPurchaseContents).Limit(limit).LimitInAppPurchaseLocalizations(limitInAppPurchaseLocalizations).LimitPricePoints(limitPricePoints).Include(include).Execute()



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
    filterInAppPurchaseType := []string{"FilterInAppPurchaseType_example"} // []string | filter by attribute 'inAppPurchaseType' (optional)
    filterName := []string{"Inner_example"} // []string | filter by attribute 'name' (optional)
    filterProductId := []string{"Inner_example"} // []string | filter by attribute 'productId' (optional)
    filterState := []string{"FilterState_example"} // []string | filter by attribute 'state' (optional)
    sort := []string{"Sort_example"} // []string | comma-separated list of sort expressions; resources will be sorted as specified (optional)
    fieldsInAppPurchaseAppStoreReviewScreenshots := []string{"FieldsInAppPurchaseAppStoreReviewScreenshots_example"} // []string | the fields to include for returned resources of type inAppPurchaseAppStoreReviewScreenshots (optional)
    fieldsInAppPurchasePricePoints := []string{"FieldsInAppPurchasePricePoints_example"} // []string | the fields to include for returned resources of type inAppPurchasePricePoints (optional)
    fieldsPromotedPurchases := []string{"FieldsPromotedPurchases_example"} // []string | the fields to include for returned resources of type promotedPurchases (optional)
    fieldsInAppPurchaseLocalizations := []string{"FieldsInAppPurchaseLocalizations_example"} // []string | the fields to include for returned resources of type inAppPurchaseLocalizations (optional)
    fieldsInAppPurchases := []string{"FieldsInAppPurchases_example"} // []string | the fields to include for returned resources of type inAppPurchases (optional)
    fieldsInAppPurchasePriceSchedules := []string{"FieldsInAppPurchasePriceSchedules_example"} // []string | the fields to include for returned resources of type inAppPurchasePriceSchedules (optional)
    fieldsInAppPurchaseContents := []string{"FieldsInAppPurchaseContents_example"} // []string | the fields to include for returned resources of type inAppPurchaseContents (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    limitInAppPurchaseLocalizations := int32(56) // int32 | maximum number of related inAppPurchaseLocalizations returned (when they are included) (optional)
    limitPricePoints := int32(56) // int32 | maximum number of related pricePoints returned (when they are included) (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppsApi.AppsInAppPurchasesV2GetToManyRelated(context.Background(), id).FilterInAppPurchaseType(filterInAppPurchaseType).FilterName(filterName).FilterProductId(filterProductId).FilterState(filterState).Sort(sort).FieldsInAppPurchaseAppStoreReviewScreenshots(fieldsInAppPurchaseAppStoreReviewScreenshots).FieldsInAppPurchasePricePoints(fieldsInAppPurchasePricePoints).FieldsPromotedPurchases(fieldsPromotedPurchases).FieldsInAppPurchaseLocalizations(fieldsInAppPurchaseLocalizations).FieldsInAppPurchases(fieldsInAppPurchases).FieldsInAppPurchasePriceSchedules(fieldsInAppPurchasePriceSchedules).FieldsInAppPurchaseContents(fieldsInAppPurchaseContents).Limit(limit).LimitInAppPurchaseLocalizations(limitInAppPurchaseLocalizations).LimitPricePoints(limitPricePoints).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppsApi.AppsInAppPurchasesV2GetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppsInAppPurchasesV2GetToManyRelated`: InAppPurchasesV2Response
    fmt.Fprintf(os.Stdout, "Response from `AppsApi.AppsInAppPurchasesV2GetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppsInAppPurchasesV2GetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **filterInAppPurchaseType** | **[]string** | filter by attribute &#39;inAppPurchaseType&#39; | 
 **filterName** | **[]string** | filter by attribute &#39;name&#39; | 
 **filterProductId** | **[]string** | filter by attribute &#39;productId&#39; | 
 **filterState** | **[]string** | filter by attribute &#39;state&#39; | 
 **sort** | **[]string** | comma-separated list of sort expressions; resources will be sorted as specified | 
 **fieldsInAppPurchaseAppStoreReviewScreenshots** | **[]string** | the fields to include for returned resources of type inAppPurchaseAppStoreReviewScreenshots | 
 **fieldsInAppPurchasePricePoints** | **[]string** | the fields to include for returned resources of type inAppPurchasePricePoints | 
 **fieldsPromotedPurchases** | **[]string** | the fields to include for returned resources of type promotedPurchases | 
 **fieldsInAppPurchaseLocalizations** | **[]string** | the fields to include for returned resources of type inAppPurchaseLocalizations | 
 **fieldsInAppPurchases** | **[]string** | the fields to include for returned resources of type inAppPurchases | 
 **fieldsInAppPurchasePriceSchedules** | **[]string** | the fields to include for returned resources of type inAppPurchasePriceSchedules | 
 **fieldsInAppPurchaseContents** | **[]string** | the fields to include for returned resources of type inAppPurchaseContents | 
 **limit** | **int32** | maximum resources per page | 
 **limitInAppPurchaseLocalizations** | **int32** | maximum number of related inAppPurchaseLocalizations returned (when they are included) | 
 **limitPricePoints** | **int32** | maximum number of related pricePoints returned (when they are included) | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**InAppPurchasesV2Response**](InAppPurchasesV2Response.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppsPerfPowerMetricsGetToManyRelated

> XcodeMetrics AppsPerfPowerMetricsGetToManyRelated(ctx, id).FilterDeviceType(filterDeviceType).FilterMetricType(filterMetricType).FilterPlatform(filterPlatform).Execute()



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
    filterDeviceType := []string{"Inner_example"} // []string | filter by attribute 'deviceType' (optional)
    filterMetricType := []string{"FilterMetricType_example"} // []string | filter by attribute 'metricType' (optional)
    filterPlatform := []string{"FilterPlatform_example"} // []string | filter by attribute 'platform' (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppsApi.AppsPerfPowerMetricsGetToManyRelated(context.Background(), id).FilterDeviceType(filterDeviceType).FilterMetricType(filterMetricType).FilterPlatform(filterPlatform).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppsApi.AppsPerfPowerMetricsGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppsPerfPowerMetricsGetToManyRelated`: XcodeMetrics
    fmt.Fprintf(os.Stdout, "Response from `AppsApi.AppsPerfPowerMetricsGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppsPerfPowerMetricsGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **filterDeviceType** | **[]string** | filter by attribute &#39;deviceType&#39; | 
 **filterMetricType** | **[]string** | filter by attribute &#39;metricType&#39; | 
 **filterPlatform** | **[]string** | filter by attribute &#39;platform&#39; | 

### Return type

[**XcodeMetrics**](XcodeMetrics.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json, application/vnd.apple.xcode-metrics+json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppsPreOrderGetToOneRelated

> AppPreOrderResponse AppsPreOrderGetToOneRelated(ctx, id).FieldsAppPreOrders(fieldsAppPreOrders).Execute()



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
    fieldsAppPreOrders := []string{"FieldsAppPreOrders_example"} // []string | the fields to include for returned resources of type appPreOrders (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppsApi.AppsPreOrderGetToOneRelated(context.Background(), id).FieldsAppPreOrders(fieldsAppPreOrders).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppsApi.AppsPreOrderGetToOneRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppsPreOrderGetToOneRelated`: AppPreOrderResponse
    fmt.Fprintf(os.Stdout, "Response from `AppsApi.AppsPreOrderGetToOneRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppsPreOrderGetToOneRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsAppPreOrders** | **[]string** | the fields to include for returned resources of type appPreOrders | 

### Return type

[**AppPreOrderResponse**](AppPreOrderResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppsPreReleaseVersionsGetToManyRelated

> PreReleaseVersionsResponse AppsPreReleaseVersionsGetToManyRelated(ctx, id).FieldsPreReleaseVersions(fieldsPreReleaseVersions).Limit(limit).Execute()



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
    fieldsPreReleaseVersions := []string{"FieldsPreReleaseVersions_example"} // []string | the fields to include for returned resources of type preReleaseVersions (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppsApi.AppsPreReleaseVersionsGetToManyRelated(context.Background(), id).FieldsPreReleaseVersions(fieldsPreReleaseVersions).Limit(limit).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppsApi.AppsPreReleaseVersionsGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppsPreReleaseVersionsGetToManyRelated`: PreReleaseVersionsResponse
    fmt.Fprintf(os.Stdout, "Response from `AppsApi.AppsPreReleaseVersionsGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppsPreReleaseVersionsGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsPreReleaseVersions** | **[]string** | the fields to include for returned resources of type preReleaseVersions | 
 **limit** | **int32** | maximum resources per page | 

### Return type

[**PreReleaseVersionsResponse**](PreReleaseVersionsResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppsPricePointsGetToManyRelated

> AppPricePointsV2Response AppsPricePointsGetToManyRelated(ctx, id).FilterPriceTier(filterPriceTier).FilterTerritory(filterTerritory).FieldsAppPriceTiers(fieldsAppPriceTiers).FieldsAppPricePoints(fieldsAppPricePoints).FieldsApps(fieldsApps).FieldsTerritories(fieldsTerritories).Limit(limit).Include(include).Execute()



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
    filterPriceTier := []string{"Inner_example"} // []string | filter by id(s) of related 'priceTier' (optional)
    filterTerritory := []string{"Inner_example"} // []string | filter by id(s) of related 'territory' (optional)
    fieldsAppPriceTiers := []string{"FieldsAppPriceTiers_example"} // []string | the fields to include for returned resources of type appPriceTiers (optional)
    fieldsAppPricePoints := []string{"FieldsAppPricePoints_example"} // []string | the fields to include for returned resources of type appPricePoints (optional)
    fieldsApps := []string{"FieldsApps_example"} // []string | the fields to include for returned resources of type apps (optional)
    fieldsTerritories := []string{"FieldsTerritories_example"} // []string | the fields to include for returned resources of type territories (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppsApi.AppsPricePointsGetToManyRelated(context.Background(), id).FilterPriceTier(filterPriceTier).FilterTerritory(filterTerritory).FieldsAppPriceTiers(fieldsAppPriceTiers).FieldsAppPricePoints(fieldsAppPricePoints).FieldsApps(fieldsApps).FieldsTerritories(fieldsTerritories).Limit(limit).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppsApi.AppsPricePointsGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppsPricePointsGetToManyRelated`: AppPricePointsV2Response
    fmt.Fprintf(os.Stdout, "Response from `AppsApi.AppsPricePointsGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppsPricePointsGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **filterPriceTier** | **[]string** | filter by id(s) of related &#39;priceTier&#39; | 
 **filterTerritory** | **[]string** | filter by id(s) of related &#39;territory&#39; | 
 **fieldsAppPriceTiers** | **[]string** | the fields to include for returned resources of type appPriceTiers | 
 **fieldsAppPricePoints** | **[]string** | the fields to include for returned resources of type appPricePoints | 
 **fieldsApps** | **[]string** | the fields to include for returned resources of type apps | 
 **fieldsTerritories** | **[]string** | the fields to include for returned resources of type territories | 
 **limit** | **int32** | maximum resources per page | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**AppPricePointsV2Response**](AppPricePointsV2Response.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppsPricesGetToManyRelated

> AppPricesResponse AppsPricesGetToManyRelated(ctx, id).FieldsAppPriceTiers(fieldsAppPriceTiers).FieldsApps(fieldsApps).FieldsAppPrices(fieldsAppPrices).Limit(limit).Include(include).Execute()



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
    fieldsAppPriceTiers := []string{"FieldsAppPriceTiers_example"} // []string | the fields to include for returned resources of type appPriceTiers (optional)
    fieldsApps := []string{"FieldsApps_example"} // []string | the fields to include for returned resources of type apps (optional)
    fieldsAppPrices := []string{"FieldsAppPrices_example"} // []string | the fields to include for returned resources of type appPrices (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppsApi.AppsPricesGetToManyRelated(context.Background(), id).FieldsAppPriceTiers(fieldsAppPriceTiers).FieldsApps(fieldsApps).FieldsAppPrices(fieldsAppPrices).Limit(limit).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppsApi.AppsPricesGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppsPricesGetToManyRelated`: AppPricesResponse
    fmt.Fprintf(os.Stdout, "Response from `AppsApi.AppsPricesGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppsPricesGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsAppPriceTiers** | **[]string** | the fields to include for returned resources of type appPriceTiers | 
 **fieldsApps** | **[]string** | the fields to include for returned resources of type apps | 
 **fieldsAppPrices** | **[]string** | the fields to include for returned resources of type appPrices | 
 **limit** | **int32** | maximum resources per page | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**AppPricesResponse**](AppPricesResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppsPromotedPurchasesGetToManyRelated

> PromotedPurchasesResponse AppsPromotedPurchasesGetToManyRelated(ctx, id).FieldsPromotedPurchases(fieldsPromotedPurchases).FieldsSubscriptions(fieldsSubscriptions).FieldsInAppPurchases(fieldsInAppPurchases).FieldsPromotedPurchaseImages(fieldsPromotedPurchaseImages).Limit(limit).LimitPromotionImages(limitPromotionImages).Include(include).Execute()



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
    fieldsPromotedPurchases := []string{"FieldsPromotedPurchases_example"} // []string | the fields to include for returned resources of type promotedPurchases (optional)
    fieldsSubscriptions := []string{"FieldsSubscriptions_example"} // []string | the fields to include for returned resources of type subscriptions (optional)
    fieldsInAppPurchases := []string{"FieldsInAppPurchases_example"} // []string | the fields to include for returned resources of type inAppPurchases (optional)
    fieldsPromotedPurchaseImages := []string{"FieldsPromotedPurchaseImages_example"} // []string | the fields to include for returned resources of type promotedPurchaseImages (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    limitPromotionImages := int32(56) // int32 | maximum number of related promotionImages returned (when they are included) (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppsApi.AppsPromotedPurchasesGetToManyRelated(context.Background(), id).FieldsPromotedPurchases(fieldsPromotedPurchases).FieldsSubscriptions(fieldsSubscriptions).FieldsInAppPurchases(fieldsInAppPurchases).FieldsPromotedPurchaseImages(fieldsPromotedPurchaseImages).Limit(limit).LimitPromotionImages(limitPromotionImages).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppsApi.AppsPromotedPurchasesGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppsPromotedPurchasesGetToManyRelated`: PromotedPurchasesResponse
    fmt.Fprintf(os.Stdout, "Response from `AppsApi.AppsPromotedPurchasesGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppsPromotedPurchasesGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsPromotedPurchases** | **[]string** | the fields to include for returned resources of type promotedPurchases | 
 **fieldsSubscriptions** | **[]string** | the fields to include for returned resources of type subscriptions | 
 **fieldsInAppPurchases** | **[]string** | the fields to include for returned resources of type inAppPurchases | 
 **fieldsPromotedPurchaseImages** | **[]string** | the fields to include for returned resources of type promotedPurchaseImages | 
 **limit** | **int32** | maximum resources per page | 
 **limitPromotionImages** | **int32** | maximum number of related promotionImages returned (when they are included) | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**PromotedPurchasesResponse**](PromotedPurchasesResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppsPromotedPurchasesGetToManyRelationship

> AppPromotedPurchasesLinkagesResponse AppsPromotedPurchasesGetToManyRelationship(ctx, id).Limit(limit).Execute()



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
    limit := int32(56) // int32 | maximum resources per page (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppsApi.AppsPromotedPurchasesGetToManyRelationship(context.Background(), id).Limit(limit).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppsApi.AppsPromotedPurchasesGetToManyRelationship``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppsPromotedPurchasesGetToManyRelationship`: AppPromotedPurchasesLinkagesResponse
    fmt.Fprintf(os.Stdout, "Response from `AppsApi.AppsPromotedPurchasesGetToManyRelationship`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppsPromotedPurchasesGetToManyRelationshipRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **limit** | **int32** | maximum resources per page | 

### Return type

[**AppPromotedPurchasesLinkagesResponse**](AppPromotedPurchasesLinkagesResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppsPromotedPurchasesReplaceToManyRelationship

> AppsPromotedPurchasesReplaceToManyRelationship(ctx, id).AppPromotedPurchasesLinkagesRequest(appPromotedPurchasesLinkagesRequest).Execute()



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
    appPromotedPurchasesLinkagesRequest := *openapiclient.NewAppPromotedPurchasesLinkagesRequest([]openapiclient.AppRelationshipsPromotedPurchasesDataInner{*openapiclient.NewAppRelationshipsPromotedPurchasesDataInner("Type_example", "Id_example")}) // AppPromotedPurchasesLinkagesRequest | List of related linkages

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    r, err := apiClient.AppsApi.AppsPromotedPurchasesReplaceToManyRelationship(context.Background(), id).AppPromotedPurchasesLinkagesRequest(appPromotedPurchasesLinkagesRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppsApi.AppsPromotedPurchasesReplaceToManyRelationship``: %v\n", err)
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

Other parameters are passed through a pointer to a apiAppsPromotedPurchasesReplaceToManyRelationshipRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **appPromotedPurchasesLinkagesRequest** | [**AppPromotedPurchasesLinkagesRequest**](AppPromotedPurchasesLinkagesRequest.md) | List of related linkages | 

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


## AppsReviewSubmissionsGetToManyRelated

> ReviewSubmissionsResponse AppsReviewSubmissionsGetToManyRelated(ctx, id).FilterPlatform(filterPlatform).FilterState(filterState).FieldsReviewSubmissionItems(fieldsReviewSubmissionItems).FieldsAppStoreVersions(fieldsAppStoreVersions).FieldsApps(fieldsApps).FieldsReviewSubmissions(fieldsReviewSubmissions).Limit(limit).LimitItems(limitItems).Include(include).Execute()



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
    filterPlatform := []string{"FilterPlatform_example"} // []string | filter by attribute 'platform' (optional)
    filterState := []string{"FilterState_example"} // []string | filter by attribute 'state' (optional)
    fieldsReviewSubmissionItems := []string{"FieldsReviewSubmissionItems_example"} // []string | the fields to include for returned resources of type reviewSubmissionItems (optional)
    fieldsAppStoreVersions := []string{"FieldsAppStoreVersions_example"} // []string | the fields to include for returned resources of type appStoreVersions (optional)
    fieldsApps := []string{"FieldsApps_example"} // []string | the fields to include for returned resources of type apps (optional)
    fieldsReviewSubmissions := []string{"FieldsReviewSubmissions_example"} // []string | the fields to include for returned resources of type reviewSubmissions (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    limitItems := int32(56) // int32 | maximum number of related items returned (when they are included) (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppsApi.AppsReviewSubmissionsGetToManyRelated(context.Background(), id).FilterPlatform(filterPlatform).FilterState(filterState).FieldsReviewSubmissionItems(fieldsReviewSubmissionItems).FieldsAppStoreVersions(fieldsAppStoreVersions).FieldsApps(fieldsApps).FieldsReviewSubmissions(fieldsReviewSubmissions).Limit(limit).LimitItems(limitItems).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppsApi.AppsReviewSubmissionsGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppsReviewSubmissionsGetToManyRelated`: ReviewSubmissionsResponse
    fmt.Fprintf(os.Stdout, "Response from `AppsApi.AppsReviewSubmissionsGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppsReviewSubmissionsGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **filterPlatform** | **[]string** | filter by attribute &#39;platform&#39; | 
 **filterState** | **[]string** | filter by attribute &#39;state&#39; | 
 **fieldsReviewSubmissionItems** | **[]string** | the fields to include for returned resources of type reviewSubmissionItems | 
 **fieldsAppStoreVersions** | **[]string** | the fields to include for returned resources of type appStoreVersions | 
 **fieldsApps** | **[]string** | the fields to include for returned resources of type apps | 
 **fieldsReviewSubmissions** | **[]string** | the fields to include for returned resources of type reviewSubmissions | 
 **limit** | **int32** | maximum resources per page | 
 **limitItems** | **int32** | maximum number of related items returned (when they are included) | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**ReviewSubmissionsResponse**](ReviewSubmissionsResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppsSubscriptionGracePeriodGetToOneRelated

> SubscriptionGracePeriodResponse AppsSubscriptionGracePeriodGetToOneRelated(ctx, id).FieldsSubscriptionGracePeriods(fieldsSubscriptionGracePeriods).Execute()



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
    fieldsSubscriptionGracePeriods := []string{"FieldsSubscriptionGracePeriods_example"} // []string | the fields to include for returned resources of type subscriptionGracePeriods (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppsApi.AppsSubscriptionGracePeriodGetToOneRelated(context.Background(), id).FieldsSubscriptionGracePeriods(fieldsSubscriptionGracePeriods).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppsApi.AppsSubscriptionGracePeriodGetToOneRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppsSubscriptionGracePeriodGetToOneRelated`: SubscriptionGracePeriodResponse
    fmt.Fprintf(os.Stdout, "Response from `AppsApi.AppsSubscriptionGracePeriodGetToOneRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppsSubscriptionGracePeriodGetToOneRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsSubscriptionGracePeriods** | **[]string** | the fields to include for returned resources of type subscriptionGracePeriods | 

### Return type

[**SubscriptionGracePeriodResponse**](SubscriptionGracePeriodResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppsSubscriptionGroupsGetToManyRelated

> SubscriptionGroupsResponse AppsSubscriptionGroupsGetToManyRelated(ctx, id).FilterReferenceName(filterReferenceName).FilterSubscriptionsState(filterSubscriptionsState).Sort(sort).FieldsSubscriptions(fieldsSubscriptions).FieldsSubscriptionGroups(fieldsSubscriptionGroups).FieldsSubscriptionGroupLocalizations(fieldsSubscriptionGroupLocalizations).Limit(limit).LimitSubscriptions(limitSubscriptions).LimitSubscriptionGroupLocalizations(limitSubscriptionGroupLocalizations).Include(include).Execute()



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
    filterReferenceName := []string{"Inner_example"} // []string | filter by attribute 'referenceName' (optional)
    filterSubscriptionsState := []string{"FilterSubscriptionsState_example"} // []string | filter by attribute 'subscriptions.state' (optional)
    sort := []string{"Sort_example"} // []string | comma-separated list of sort expressions; resources will be sorted as specified (optional)
    fieldsSubscriptions := []string{"FieldsSubscriptions_example"} // []string | the fields to include for returned resources of type subscriptions (optional)
    fieldsSubscriptionGroups := []string{"FieldsSubscriptionGroups_example"} // []string | the fields to include for returned resources of type subscriptionGroups (optional)
    fieldsSubscriptionGroupLocalizations := []string{"FieldsSubscriptionGroupLocalizations_example"} // []string | the fields to include for returned resources of type subscriptionGroupLocalizations (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    limitSubscriptions := int32(56) // int32 | maximum number of related subscriptions returned (when they are included) (optional)
    limitSubscriptionGroupLocalizations := int32(56) // int32 | maximum number of related subscriptionGroupLocalizations returned (when they are included) (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppsApi.AppsSubscriptionGroupsGetToManyRelated(context.Background(), id).FilterReferenceName(filterReferenceName).FilterSubscriptionsState(filterSubscriptionsState).Sort(sort).FieldsSubscriptions(fieldsSubscriptions).FieldsSubscriptionGroups(fieldsSubscriptionGroups).FieldsSubscriptionGroupLocalizations(fieldsSubscriptionGroupLocalizations).Limit(limit).LimitSubscriptions(limitSubscriptions).LimitSubscriptionGroupLocalizations(limitSubscriptionGroupLocalizations).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppsApi.AppsSubscriptionGroupsGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppsSubscriptionGroupsGetToManyRelated`: SubscriptionGroupsResponse
    fmt.Fprintf(os.Stdout, "Response from `AppsApi.AppsSubscriptionGroupsGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppsSubscriptionGroupsGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **filterReferenceName** | **[]string** | filter by attribute &#39;referenceName&#39; | 
 **filterSubscriptionsState** | **[]string** | filter by attribute &#39;subscriptions.state&#39; | 
 **sort** | **[]string** | comma-separated list of sort expressions; resources will be sorted as specified | 
 **fieldsSubscriptions** | **[]string** | the fields to include for returned resources of type subscriptions | 
 **fieldsSubscriptionGroups** | **[]string** | the fields to include for returned resources of type subscriptionGroups | 
 **fieldsSubscriptionGroupLocalizations** | **[]string** | the fields to include for returned resources of type subscriptionGroupLocalizations | 
 **limit** | **int32** | maximum resources per page | 
 **limitSubscriptions** | **int32** | maximum number of related subscriptions returned (when they are included) | 
 **limitSubscriptionGroupLocalizations** | **int32** | maximum number of related subscriptionGroupLocalizations returned (when they are included) | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**SubscriptionGroupsResponse**](SubscriptionGroupsResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppsUpdateInstance

> AppResponse AppsUpdateInstance(ctx, id).AppUpdateRequest(appUpdateRequest).Execute()



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
    appUpdateRequest := *openapiclient.NewAppUpdateRequest(*openapiclient.NewAppUpdateRequestData("Type_example", "Id_example")) // AppUpdateRequest | App representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppsApi.AppsUpdateInstance(context.Background(), id).AppUpdateRequest(appUpdateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppsApi.AppsUpdateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppsUpdateInstance`: AppResponse
    fmt.Fprintf(os.Stdout, "Response from `AppsApi.AppsUpdateInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppsUpdateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **appUpdateRequest** | [**AppUpdateRequest**](AppUpdateRequest.md) | App representation | 

### Return type

[**AppResponse**](AppResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

