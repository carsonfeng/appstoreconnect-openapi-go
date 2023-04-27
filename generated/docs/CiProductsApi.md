# \CiProductsApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**CiProductsAdditionalRepositoriesGetToManyRelated**](CiProductsApi.md#CiProductsAdditionalRepositoriesGetToManyRelated) | **Get** /v1/ciProducts/{id}/additionalRepositories | 
[**CiProductsAppGetToOneRelated**](CiProductsApi.md#CiProductsAppGetToOneRelated) | **Get** /v1/ciProducts/{id}/app | 
[**CiProductsBuildRunsGetToManyRelated**](CiProductsApi.md#CiProductsBuildRunsGetToManyRelated) | **Get** /v1/ciProducts/{id}/buildRuns | 
[**CiProductsDeleteInstance**](CiProductsApi.md#CiProductsDeleteInstance) | **Delete** /v1/ciProducts/{id} | 
[**CiProductsGetCollection**](CiProductsApi.md#CiProductsGetCollection) | **Get** /v1/ciProducts | 
[**CiProductsGetInstance**](CiProductsApi.md#CiProductsGetInstance) | **Get** /v1/ciProducts/{id} | 
[**CiProductsPrimaryRepositoriesGetToManyRelated**](CiProductsApi.md#CiProductsPrimaryRepositoriesGetToManyRelated) | **Get** /v1/ciProducts/{id}/primaryRepositories | 
[**CiProductsWorkflowsGetToManyRelated**](CiProductsApi.md#CiProductsWorkflowsGetToManyRelated) | **Get** /v1/ciProducts/{id}/workflows | 



## CiProductsAdditionalRepositoriesGetToManyRelated

> ScmRepositoriesResponse CiProductsAdditionalRepositoriesGetToManyRelated(ctx, id).FilterId(filterId).FieldsScmGitReferences(fieldsScmGitReferences).FieldsScmProviders(fieldsScmProviders).FieldsScmRepositories(fieldsScmRepositories).Limit(limit).Include(include).Execute()



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
    filterId := []string{"Inner_example"} // []string | filter by id(s) (optional)
    fieldsScmGitReferences := []string{"FieldsScmGitReferences_example"} // []string | the fields to include for returned resources of type scmGitReferences (optional)
    fieldsScmProviders := []string{"FieldsScmProviders_example"} // []string | the fields to include for returned resources of type scmProviders (optional)
    fieldsScmRepositories := []string{"FieldsScmRepositories_example"} // []string | the fields to include for returned resources of type scmRepositories (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.CiProductsApi.CiProductsAdditionalRepositoriesGetToManyRelated(context.Background(), id).FilterId(filterId).FieldsScmGitReferences(fieldsScmGitReferences).FieldsScmProviders(fieldsScmProviders).FieldsScmRepositories(fieldsScmRepositories).Limit(limit).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `CiProductsApi.CiProductsAdditionalRepositoriesGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `CiProductsAdditionalRepositoriesGetToManyRelated`: ScmRepositoriesResponse
    fmt.Fprintf(os.Stdout, "Response from `CiProductsApi.CiProductsAdditionalRepositoriesGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiCiProductsAdditionalRepositoriesGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **filterId** | **[]string** | filter by id(s) | 
 **fieldsScmGitReferences** | **[]string** | the fields to include for returned resources of type scmGitReferences | 
 **fieldsScmProviders** | **[]string** | the fields to include for returned resources of type scmProviders | 
 **fieldsScmRepositories** | **[]string** | the fields to include for returned resources of type scmRepositories | 
 **limit** | **int32** | maximum resources per page | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**ScmRepositoriesResponse**](ScmRepositoriesResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## CiProductsAppGetToOneRelated

> AppResponse CiProductsAppGetToOneRelated(ctx, id).FieldsBetaLicenseAgreements(fieldsBetaLicenseAgreements).FieldsBetaAppReviewDetails(fieldsBetaAppReviewDetails).FieldsAppClips(fieldsAppClips).FieldsBetaAppLocalizations(fieldsBetaAppLocalizations).FieldsAppInfos(fieldsAppInfos).FieldsPreReleaseVersions(fieldsPreReleaseVersions).FieldsInAppPurchases(fieldsInAppPurchases).FieldsCiProducts(fieldsCiProducts).FieldsInAppPurchases2(fieldsInAppPurchases2).FieldsSubscriptionGroups(fieldsSubscriptionGroups).FieldsReviewSubmissions(fieldsReviewSubmissions).FieldsBetaGroups(fieldsBetaGroups).FieldsAppPreOrders(fieldsAppPreOrders).FieldsAppPrices(fieldsAppPrices).FieldsGameCenterEnabledVersions(fieldsGameCenterEnabledVersions).FieldsSubscriptionGracePeriods(fieldsSubscriptionGracePeriods).FieldsPromotedPurchases(fieldsPromotedPurchases).FieldsEndUserLicenseAgreements(fieldsEndUserLicenseAgreements).FieldsAppStoreVersions(fieldsAppStoreVersions).FieldsAppCustomProductPages(fieldsAppCustomProductPages).FieldsApps(fieldsApps).FieldsAppEvents(fieldsAppEvents).FieldsTerritories(fieldsTerritories).FieldsBuilds(fieldsBuilds).LimitBetaGroups(limitBetaGroups).LimitAppStoreVersions(limitAppStoreVersions).LimitPreReleaseVersions(limitPreReleaseVersions).LimitBetaAppLocalizations(limitBetaAppLocalizations).LimitBuilds(limitBuilds).LimitAppInfos(limitAppInfos).LimitAppClips(limitAppClips).LimitPrices(limitPrices).LimitAvailableTerritories(limitAvailableTerritories).LimitInAppPurchases(limitInAppPurchases).LimitSubscriptionGroups(limitSubscriptionGroups).LimitGameCenterEnabledVersions(limitGameCenterEnabledVersions).LimitAppCustomProductPages(limitAppCustomProductPages).LimitInAppPurchasesV2(limitInAppPurchasesV2).LimitPromotedPurchases(limitPromotedPurchases).LimitAppEvents(limitAppEvents).LimitReviewSubmissions(limitReviewSubmissions).Include(include).Execute()



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
    fieldsBetaAppReviewDetails := []string{"FieldsBetaAppReviewDetails_example"} // []string | the fields to include for returned resources of type betaAppReviewDetails (optional)
    fieldsAppClips := []string{"FieldsAppClips_example"} // []string | the fields to include for returned resources of type appClips (optional)
    fieldsBetaAppLocalizations := []string{"FieldsBetaAppLocalizations_example"} // []string | the fields to include for returned resources of type betaAppLocalizations (optional)
    fieldsAppInfos := []string{"FieldsAppInfos_example"} // []string | the fields to include for returned resources of type appInfos (optional)
    fieldsPreReleaseVersions := []string{"FieldsPreReleaseVersions_example"} // []string | the fields to include for returned resources of type preReleaseVersions (optional)
    fieldsInAppPurchases := []string{"FieldsInAppPurchases_example"} // []string | the fields to include for returned resources of type inAppPurchases (optional)
    fieldsCiProducts := []string{"FieldsCiProducts_example"} // []string | the fields to include for returned resources of type ciProducts (optional)
    fieldsInAppPurchases2 := []string{"FieldsInAppPurchases_example"} // []string | the fields to include for returned resources of type inAppPurchases (optional)
    fieldsSubscriptionGroups := []string{"FieldsSubscriptionGroups_example"} // []string | the fields to include for returned resources of type subscriptionGroups (optional)
    fieldsReviewSubmissions := []string{"FieldsReviewSubmissions_example"} // []string | the fields to include for returned resources of type reviewSubmissions (optional)
    fieldsBetaGroups := []string{"FieldsBetaGroups_example"} // []string | the fields to include for returned resources of type betaGroups (optional)
    fieldsAppPreOrders := []string{"FieldsAppPreOrders_example"} // []string | the fields to include for returned resources of type appPreOrders (optional)
    fieldsAppPrices := []string{"FieldsAppPrices_example"} // []string | the fields to include for returned resources of type appPrices (optional)
    fieldsGameCenterEnabledVersions := []string{"FieldsGameCenterEnabledVersions_example"} // []string | the fields to include for returned resources of type gameCenterEnabledVersions (optional)
    fieldsSubscriptionGracePeriods := []string{"FieldsSubscriptionGracePeriods_example"} // []string | the fields to include for returned resources of type subscriptionGracePeriods (optional)
    fieldsPromotedPurchases := []string{"FieldsPromotedPurchases_example"} // []string | the fields to include for returned resources of type promotedPurchases (optional)
    fieldsEndUserLicenseAgreements := []string{"FieldsEndUserLicenseAgreements_example"} // []string | the fields to include for returned resources of type endUserLicenseAgreements (optional)
    fieldsAppStoreVersions := []string{"FieldsAppStoreVersions_example"} // []string | the fields to include for returned resources of type appStoreVersions (optional)
    fieldsAppCustomProductPages := []string{"FieldsAppCustomProductPages_example"} // []string | the fields to include for returned resources of type appCustomProductPages (optional)
    fieldsApps := []string{"FieldsApps_example"} // []string | the fields to include for returned resources of type apps (optional)
    fieldsAppEvents := []string{"FieldsAppEvents_example"} // []string | the fields to include for returned resources of type appEvents (optional)
    fieldsTerritories := []string{"FieldsTerritories_example"} // []string | the fields to include for returned resources of type territories (optional)
    fieldsBuilds := []string{"FieldsBuilds_example"} // []string | the fields to include for returned resources of type builds (optional)
    limitBetaGroups := int32(56) // int32 | maximum number of related betaGroups returned (when they are included) (optional)
    limitAppStoreVersions := int32(56) // int32 | maximum number of related appStoreVersions returned (when they are included) (optional)
    limitPreReleaseVersions := int32(56) // int32 | maximum number of related preReleaseVersions returned (when they are included) (optional)
    limitBetaAppLocalizations := int32(56) // int32 | maximum number of related betaAppLocalizations returned (when they are included) (optional)
    limitBuilds := int32(56) // int32 | maximum number of related builds returned (when they are included) (optional)
    limitAppInfos := int32(56) // int32 | maximum number of related appInfos returned (when they are included) (optional)
    limitAppClips := int32(56) // int32 | maximum number of related appClips returned (when they are included) (optional)
    limitPrices := int32(56) // int32 | maximum number of related prices returned (when they are included) (optional)
    limitAvailableTerritories := int32(56) // int32 | maximum number of related availableTerritories returned (when they are included) (optional)
    limitInAppPurchases := int32(56) // int32 | maximum number of related inAppPurchases returned (when they are included) (optional)
    limitSubscriptionGroups := int32(56) // int32 | maximum number of related subscriptionGroups returned (when they are included) (optional)
    limitGameCenterEnabledVersions := int32(56) // int32 | maximum number of related gameCenterEnabledVersions returned (when they are included) (optional)
    limitAppCustomProductPages := int32(56) // int32 | maximum number of related appCustomProductPages returned (when they are included) (optional)
    limitInAppPurchasesV2 := int32(56) // int32 | maximum number of related inAppPurchasesV2 returned (when they are included) (optional)
    limitPromotedPurchases := int32(56) // int32 | maximum number of related promotedPurchases returned (when they are included) (optional)
    limitAppEvents := int32(56) // int32 | maximum number of related appEvents returned (when they are included) (optional)
    limitReviewSubmissions := int32(56) // int32 | maximum number of related reviewSubmissions returned (when they are included) (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.CiProductsApi.CiProductsAppGetToOneRelated(context.Background(), id).FieldsBetaLicenseAgreements(fieldsBetaLicenseAgreements).FieldsBetaAppReviewDetails(fieldsBetaAppReviewDetails).FieldsAppClips(fieldsAppClips).FieldsBetaAppLocalizations(fieldsBetaAppLocalizations).FieldsAppInfos(fieldsAppInfos).FieldsPreReleaseVersions(fieldsPreReleaseVersions).FieldsInAppPurchases(fieldsInAppPurchases).FieldsCiProducts(fieldsCiProducts).FieldsInAppPurchases2(fieldsInAppPurchases2).FieldsSubscriptionGroups(fieldsSubscriptionGroups).FieldsReviewSubmissions(fieldsReviewSubmissions).FieldsBetaGroups(fieldsBetaGroups).FieldsAppPreOrders(fieldsAppPreOrders).FieldsAppPrices(fieldsAppPrices).FieldsGameCenterEnabledVersions(fieldsGameCenterEnabledVersions).FieldsSubscriptionGracePeriods(fieldsSubscriptionGracePeriods).FieldsPromotedPurchases(fieldsPromotedPurchases).FieldsEndUserLicenseAgreements(fieldsEndUserLicenseAgreements).FieldsAppStoreVersions(fieldsAppStoreVersions).FieldsAppCustomProductPages(fieldsAppCustomProductPages).FieldsApps(fieldsApps).FieldsAppEvents(fieldsAppEvents).FieldsTerritories(fieldsTerritories).FieldsBuilds(fieldsBuilds).LimitBetaGroups(limitBetaGroups).LimitAppStoreVersions(limitAppStoreVersions).LimitPreReleaseVersions(limitPreReleaseVersions).LimitBetaAppLocalizations(limitBetaAppLocalizations).LimitBuilds(limitBuilds).LimitAppInfos(limitAppInfos).LimitAppClips(limitAppClips).LimitPrices(limitPrices).LimitAvailableTerritories(limitAvailableTerritories).LimitInAppPurchases(limitInAppPurchases).LimitSubscriptionGroups(limitSubscriptionGroups).LimitGameCenterEnabledVersions(limitGameCenterEnabledVersions).LimitAppCustomProductPages(limitAppCustomProductPages).LimitInAppPurchasesV2(limitInAppPurchasesV2).LimitPromotedPurchases(limitPromotedPurchases).LimitAppEvents(limitAppEvents).LimitReviewSubmissions(limitReviewSubmissions).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `CiProductsApi.CiProductsAppGetToOneRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `CiProductsAppGetToOneRelated`: AppResponse
    fmt.Fprintf(os.Stdout, "Response from `CiProductsApi.CiProductsAppGetToOneRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiCiProductsAppGetToOneRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsBetaLicenseAgreements** | **[]string** | the fields to include for returned resources of type betaLicenseAgreements | 
 **fieldsBetaAppReviewDetails** | **[]string** | the fields to include for returned resources of type betaAppReviewDetails | 
 **fieldsAppClips** | **[]string** | the fields to include for returned resources of type appClips | 
 **fieldsBetaAppLocalizations** | **[]string** | the fields to include for returned resources of type betaAppLocalizations | 
 **fieldsAppInfos** | **[]string** | the fields to include for returned resources of type appInfos | 
 **fieldsPreReleaseVersions** | **[]string** | the fields to include for returned resources of type preReleaseVersions | 
 **fieldsInAppPurchases** | **[]string** | the fields to include for returned resources of type inAppPurchases | 
 **fieldsCiProducts** | **[]string** | the fields to include for returned resources of type ciProducts | 
 **fieldsInAppPurchases2** | **[]string** | the fields to include for returned resources of type inAppPurchases | 
 **fieldsSubscriptionGroups** | **[]string** | the fields to include for returned resources of type subscriptionGroups | 
 **fieldsReviewSubmissions** | **[]string** | the fields to include for returned resources of type reviewSubmissions | 
 **fieldsBetaGroups** | **[]string** | the fields to include for returned resources of type betaGroups | 
 **fieldsAppPreOrders** | **[]string** | the fields to include for returned resources of type appPreOrders | 
 **fieldsAppPrices** | **[]string** | the fields to include for returned resources of type appPrices | 
 **fieldsGameCenterEnabledVersions** | **[]string** | the fields to include for returned resources of type gameCenterEnabledVersions | 
 **fieldsSubscriptionGracePeriods** | **[]string** | the fields to include for returned resources of type subscriptionGracePeriods | 
 **fieldsPromotedPurchases** | **[]string** | the fields to include for returned resources of type promotedPurchases | 
 **fieldsEndUserLicenseAgreements** | **[]string** | the fields to include for returned resources of type endUserLicenseAgreements | 
 **fieldsAppStoreVersions** | **[]string** | the fields to include for returned resources of type appStoreVersions | 
 **fieldsAppCustomProductPages** | **[]string** | the fields to include for returned resources of type appCustomProductPages | 
 **fieldsApps** | **[]string** | the fields to include for returned resources of type apps | 
 **fieldsAppEvents** | **[]string** | the fields to include for returned resources of type appEvents | 
 **fieldsTerritories** | **[]string** | the fields to include for returned resources of type territories | 
 **fieldsBuilds** | **[]string** | the fields to include for returned resources of type builds | 
 **limitBetaGroups** | **int32** | maximum number of related betaGroups returned (when they are included) | 
 **limitAppStoreVersions** | **int32** | maximum number of related appStoreVersions returned (when they are included) | 
 **limitPreReleaseVersions** | **int32** | maximum number of related preReleaseVersions returned (when they are included) | 
 **limitBetaAppLocalizations** | **int32** | maximum number of related betaAppLocalizations returned (when they are included) | 
 **limitBuilds** | **int32** | maximum number of related builds returned (when they are included) | 
 **limitAppInfos** | **int32** | maximum number of related appInfos returned (when they are included) | 
 **limitAppClips** | **int32** | maximum number of related appClips returned (when they are included) | 
 **limitPrices** | **int32** | maximum number of related prices returned (when they are included) | 
 **limitAvailableTerritories** | **int32** | maximum number of related availableTerritories returned (when they are included) | 
 **limitInAppPurchases** | **int32** | maximum number of related inAppPurchases returned (when they are included) | 
 **limitSubscriptionGroups** | **int32** | maximum number of related subscriptionGroups returned (when they are included) | 
 **limitGameCenterEnabledVersions** | **int32** | maximum number of related gameCenterEnabledVersions returned (when they are included) | 
 **limitAppCustomProductPages** | **int32** | maximum number of related appCustomProductPages returned (when they are included) | 
 **limitInAppPurchasesV2** | **int32** | maximum number of related inAppPurchasesV2 returned (when they are included) | 
 **limitPromotedPurchases** | **int32** | maximum number of related promotedPurchases returned (when they are included) | 
 **limitAppEvents** | **int32** | maximum number of related appEvents returned (when they are included) | 
 **limitReviewSubmissions** | **int32** | maximum number of related reviewSubmissions returned (when they are included) | 
 **include** | **[]string** | comma-separated list of relationships to include | 

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


## CiProductsBuildRunsGetToManyRelated

> CiBuildRunsResponse CiProductsBuildRunsGetToManyRelated(ctx, id).FilterBuilds(filterBuilds).FieldsScmGitReferences(fieldsScmGitReferences).FieldsCiBuildRuns(fieldsCiBuildRuns).FieldsCiWorkflows(fieldsCiWorkflows).FieldsScmPullRequests(fieldsScmPullRequests).FieldsCiProducts(fieldsCiProducts).FieldsBuilds(fieldsBuilds).Limit(limit).LimitBuilds(limitBuilds).Include(include).Execute()



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
    filterBuilds := []string{"Inner_example"} // []string | filter by id(s) of related 'builds' (optional)
    fieldsScmGitReferences := []string{"FieldsScmGitReferences_example"} // []string | the fields to include for returned resources of type scmGitReferences (optional)
    fieldsCiBuildRuns := []string{"FieldsCiBuildRuns_example"} // []string | the fields to include for returned resources of type ciBuildRuns (optional)
    fieldsCiWorkflows := []string{"FieldsCiWorkflows_example"} // []string | the fields to include for returned resources of type ciWorkflows (optional)
    fieldsScmPullRequests := []string{"FieldsScmPullRequests_example"} // []string | the fields to include for returned resources of type scmPullRequests (optional)
    fieldsCiProducts := []string{"FieldsCiProducts_example"} // []string | the fields to include for returned resources of type ciProducts (optional)
    fieldsBuilds := []string{"FieldsBuilds_example"} // []string | the fields to include for returned resources of type builds (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    limitBuilds := int32(56) // int32 | maximum number of related builds returned (when they are included) (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.CiProductsApi.CiProductsBuildRunsGetToManyRelated(context.Background(), id).FilterBuilds(filterBuilds).FieldsScmGitReferences(fieldsScmGitReferences).FieldsCiBuildRuns(fieldsCiBuildRuns).FieldsCiWorkflows(fieldsCiWorkflows).FieldsScmPullRequests(fieldsScmPullRequests).FieldsCiProducts(fieldsCiProducts).FieldsBuilds(fieldsBuilds).Limit(limit).LimitBuilds(limitBuilds).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `CiProductsApi.CiProductsBuildRunsGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `CiProductsBuildRunsGetToManyRelated`: CiBuildRunsResponse
    fmt.Fprintf(os.Stdout, "Response from `CiProductsApi.CiProductsBuildRunsGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiCiProductsBuildRunsGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **filterBuilds** | **[]string** | filter by id(s) of related &#39;builds&#39; | 
 **fieldsScmGitReferences** | **[]string** | the fields to include for returned resources of type scmGitReferences | 
 **fieldsCiBuildRuns** | **[]string** | the fields to include for returned resources of type ciBuildRuns | 
 **fieldsCiWorkflows** | **[]string** | the fields to include for returned resources of type ciWorkflows | 
 **fieldsScmPullRequests** | **[]string** | the fields to include for returned resources of type scmPullRequests | 
 **fieldsCiProducts** | **[]string** | the fields to include for returned resources of type ciProducts | 
 **fieldsBuilds** | **[]string** | the fields to include for returned resources of type builds | 
 **limit** | **int32** | maximum resources per page | 
 **limitBuilds** | **int32** | maximum number of related builds returned (when they are included) | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**CiBuildRunsResponse**](CiBuildRunsResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## CiProductsDeleteInstance

> CiProductsDeleteInstance(ctx, id).Execute()



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
    r, err := apiClient.CiProductsApi.CiProductsDeleteInstance(context.Background(), id).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `CiProductsApi.CiProductsDeleteInstance``: %v\n", err)
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

Other parameters are passed through a pointer to a apiCiProductsDeleteInstanceRequest struct via the builder pattern


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


## CiProductsGetCollection

> CiProductsResponse CiProductsGetCollection(ctx).FilterProductType(filterProductType).FilterApp(filterApp).FieldsCiProducts(fieldsCiProducts).Limit(limit).Include(include).FieldsCiBuildRuns(fieldsCiBuildRuns).FieldsCiWorkflows(fieldsCiWorkflows).FieldsApps(fieldsApps).FieldsScmRepositories(fieldsScmRepositories).LimitPrimaryRepositories(limitPrimaryRepositories).Execute()



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
    filterProductType := []string{"FilterProductType_example"} // []string | filter by attribute 'productType' (optional)
    filterApp := []string{"Inner_example"} // []string | filter by id(s) of related 'app' (optional)
    fieldsCiProducts := []string{"FieldsCiProducts_example"} // []string | the fields to include for returned resources of type ciProducts (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)
    fieldsCiBuildRuns := []string{"FieldsCiBuildRuns_example"} // []string | the fields to include for returned resources of type ciBuildRuns (optional)
    fieldsCiWorkflows := []string{"FieldsCiWorkflows_example"} // []string | the fields to include for returned resources of type ciWorkflows (optional)
    fieldsApps := []string{"FieldsApps_example"} // []string | the fields to include for returned resources of type apps (optional)
    fieldsScmRepositories := []string{"FieldsScmRepositories_example"} // []string | the fields to include for returned resources of type scmRepositories (optional)
    limitPrimaryRepositories := int32(56) // int32 | maximum number of related primaryRepositories returned (when they are included) (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.CiProductsApi.CiProductsGetCollection(context.Background()).FilterProductType(filterProductType).FilterApp(filterApp).FieldsCiProducts(fieldsCiProducts).Limit(limit).Include(include).FieldsCiBuildRuns(fieldsCiBuildRuns).FieldsCiWorkflows(fieldsCiWorkflows).FieldsApps(fieldsApps).FieldsScmRepositories(fieldsScmRepositories).LimitPrimaryRepositories(limitPrimaryRepositories).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `CiProductsApi.CiProductsGetCollection``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `CiProductsGetCollection`: CiProductsResponse
    fmt.Fprintf(os.Stdout, "Response from `CiProductsApi.CiProductsGetCollection`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiCiProductsGetCollectionRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **filterProductType** | **[]string** | filter by attribute &#39;productType&#39; | 
 **filterApp** | **[]string** | filter by id(s) of related &#39;app&#39; | 
 **fieldsCiProducts** | **[]string** | the fields to include for returned resources of type ciProducts | 
 **limit** | **int32** | maximum resources per page | 
 **include** | **[]string** | comma-separated list of relationships to include | 
 **fieldsCiBuildRuns** | **[]string** | the fields to include for returned resources of type ciBuildRuns | 
 **fieldsCiWorkflows** | **[]string** | the fields to include for returned resources of type ciWorkflows | 
 **fieldsApps** | **[]string** | the fields to include for returned resources of type apps | 
 **fieldsScmRepositories** | **[]string** | the fields to include for returned resources of type scmRepositories | 
 **limitPrimaryRepositories** | **int32** | maximum number of related primaryRepositories returned (when they are included) | 

### Return type

[**CiProductsResponse**](CiProductsResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## CiProductsGetInstance

> CiProductResponse CiProductsGetInstance(ctx, id).FieldsCiProducts(fieldsCiProducts).Include(include).FieldsCiBuildRuns(fieldsCiBuildRuns).FieldsCiWorkflows(fieldsCiWorkflows).FieldsApps(fieldsApps).FieldsScmRepositories(fieldsScmRepositories).LimitPrimaryRepositories(limitPrimaryRepositories).Execute()



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
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)
    fieldsCiBuildRuns := []string{"FieldsCiBuildRuns_example"} // []string | the fields to include for returned resources of type ciBuildRuns (optional)
    fieldsCiWorkflows := []string{"FieldsCiWorkflows_example"} // []string | the fields to include for returned resources of type ciWorkflows (optional)
    fieldsApps := []string{"FieldsApps_example"} // []string | the fields to include for returned resources of type apps (optional)
    fieldsScmRepositories := []string{"FieldsScmRepositories_example"} // []string | the fields to include for returned resources of type scmRepositories (optional)
    limitPrimaryRepositories := int32(56) // int32 | maximum number of related primaryRepositories returned (when they are included) (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.CiProductsApi.CiProductsGetInstance(context.Background(), id).FieldsCiProducts(fieldsCiProducts).Include(include).FieldsCiBuildRuns(fieldsCiBuildRuns).FieldsCiWorkflows(fieldsCiWorkflows).FieldsApps(fieldsApps).FieldsScmRepositories(fieldsScmRepositories).LimitPrimaryRepositories(limitPrimaryRepositories).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `CiProductsApi.CiProductsGetInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `CiProductsGetInstance`: CiProductResponse
    fmt.Fprintf(os.Stdout, "Response from `CiProductsApi.CiProductsGetInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiCiProductsGetInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsCiProducts** | **[]string** | the fields to include for returned resources of type ciProducts | 
 **include** | **[]string** | comma-separated list of relationships to include | 
 **fieldsCiBuildRuns** | **[]string** | the fields to include for returned resources of type ciBuildRuns | 
 **fieldsCiWorkflows** | **[]string** | the fields to include for returned resources of type ciWorkflows | 
 **fieldsApps** | **[]string** | the fields to include for returned resources of type apps | 
 **fieldsScmRepositories** | **[]string** | the fields to include for returned resources of type scmRepositories | 
 **limitPrimaryRepositories** | **int32** | maximum number of related primaryRepositories returned (when they are included) | 

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


## CiProductsPrimaryRepositoriesGetToManyRelated

> ScmRepositoriesResponse CiProductsPrimaryRepositoriesGetToManyRelated(ctx, id).FilterId(filterId).FieldsScmGitReferences(fieldsScmGitReferences).FieldsScmProviders(fieldsScmProviders).FieldsScmRepositories(fieldsScmRepositories).Limit(limit).Include(include).Execute()



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
    filterId := []string{"Inner_example"} // []string | filter by id(s) (optional)
    fieldsScmGitReferences := []string{"FieldsScmGitReferences_example"} // []string | the fields to include for returned resources of type scmGitReferences (optional)
    fieldsScmProviders := []string{"FieldsScmProviders_example"} // []string | the fields to include for returned resources of type scmProviders (optional)
    fieldsScmRepositories := []string{"FieldsScmRepositories_example"} // []string | the fields to include for returned resources of type scmRepositories (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.CiProductsApi.CiProductsPrimaryRepositoriesGetToManyRelated(context.Background(), id).FilterId(filterId).FieldsScmGitReferences(fieldsScmGitReferences).FieldsScmProviders(fieldsScmProviders).FieldsScmRepositories(fieldsScmRepositories).Limit(limit).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `CiProductsApi.CiProductsPrimaryRepositoriesGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `CiProductsPrimaryRepositoriesGetToManyRelated`: ScmRepositoriesResponse
    fmt.Fprintf(os.Stdout, "Response from `CiProductsApi.CiProductsPrimaryRepositoriesGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiCiProductsPrimaryRepositoriesGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **filterId** | **[]string** | filter by id(s) | 
 **fieldsScmGitReferences** | **[]string** | the fields to include for returned resources of type scmGitReferences | 
 **fieldsScmProviders** | **[]string** | the fields to include for returned resources of type scmProviders | 
 **fieldsScmRepositories** | **[]string** | the fields to include for returned resources of type scmRepositories | 
 **limit** | **int32** | maximum resources per page | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**ScmRepositoriesResponse**](ScmRepositoriesResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## CiProductsWorkflowsGetToManyRelated

> CiWorkflowsResponse CiProductsWorkflowsGetToManyRelated(ctx, id).FieldsCiXcodeVersions(fieldsCiXcodeVersions).FieldsCiWorkflows(fieldsCiWorkflows).FieldsCiMacOsVersions(fieldsCiMacOsVersions).FieldsCiProducts(fieldsCiProducts).FieldsScmRepositories(fieldsScmRepositories).Limit(limit).Include(include).Execute()



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
    fieldsCiXcodeVersions := []string{"FieldsCiXcodeVersions_example"} // []string | the fields to include for returned resources of type ciXcodeVersions (optional)
    fieldsCiWorkflows := []string{"FieldsCiWorkflows_example"} // []string | the fields to include for returned resources of type ciWorkflows (optional)
    fieldsCiMacOsVersions := []string{"FieldsCiMacOsVersions_example"} // []string | the fields to include for returned resources of type ciMacOsVersions (optional)
    fieldsCiProducts := []string{"FieldsCiProducts_example"} // []string | the fields to include for returned resources of type ciProducts (optional)
    fieldsScmRepositories := []string{"FieldsScmRepositories_example"} // []string | the fields to include for returned resources of type scmRepositories (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.CiProductsApi.CiProductsWorkflowsGetToManyRelated(context.Background(), id).FieldsCiXcodeVersions(fieldsCiXcodeVersions).FieldsCiWorkflows(fieldsCiWorkflows).FieldsCiMacOsVersions(fieldsCiMacOsVersions).FieldsCiProducts(fieldsCiProducts).FieldsScmRepositories(fieldsScmRepositories).Limit(limit).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `CiProductsApi.CiProductsWorkflowsGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `CiProductsWorkflowsGetToManyRelated`: CiWorkflowsResponse
    fmt.Fprintf(os.Stdout, "Response from `CiProductsApi.CiProductsWorkflowsGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiCiProductsWorkflowsGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsCiXcodeVersions** | **[]string** | the fields to include for returned resources of type ciXcodeVersions | 
 **fieldsCiWorkflows** | **[]string** | the fields to include for returned resources of type ciWorkflows | 
 **fieldsCiMacOsVersions** | **[]string** | the fields to include for returned resources of type ciMacOsVersions | 
 **fieldsCiProducts** | **[]string** | the fields to include for returned resources of type ciProducts | 
 **fieldsScmRepositories** | **[]string** | the fields to include for returned resources of type scmRepositories | 
 **limit** | **int32** | maximum resources per page | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**CiWorkflowsResponse**](CiWorkflowsResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

