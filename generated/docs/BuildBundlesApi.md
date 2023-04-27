# \BuildBundlesApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**BuildBundlesAppClipDomainCacheStatusGetToOneRelated**](BuildBundlesApi.md#BuildBundlesAppClipDomainCacheStatusGetToOneRelated) | **Get** /v1/buildBundles/{id}/appClipDomainCacheStatus | 
[**BuildBundlesAppClipDomainDebugStatusGetToOneRelated**](BuildBundlesApi.md#BuildBundlesAppClipDomainDebugStatusGetToOneRelated) | **Get** /v1/buildBundles/{id}/appClipDomainDebugStatus | 
[**BuildBundlesBetaAppClipInvocationsGetToManyRelated**](BuildBundlesApi.md#BuildBundlesBetaAppClipInvocationsGetToManyRelated) | **Get** /v1/buildBundles/{id}/betaAppClipInvocations | 
[**BuildBundlesBuildBundleFileSizesGetToManyRelated**](BuildBundlesApi.md#BuildBundlesBuildBundleFileSizesGetToManyRelated) | **Get** /v1/buildBundles/{id}/buildBundleFileSizes | 



## BuildBundlesAppClipDomainCacheStatusGetToOneRelated

> AppClipDomainStatusResponse BuildBundlesAppClipDomainCacheStatusGetToOneRelated(ctx, id).FieldsAppClipDomainStatuses(fieldsAppClipDomainStatuses).Execute()



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
    fieldsAppClipDomainStatuses := []string{"FieldsAppClipDomainStatuses_example"} // []string | the fields to include for returned resources of type appClipDomainStatuses (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.BuildBundlesApi.BuildBundlesAppClipDomainCacheStatusGetToOneRelated(context.Background(), id).FieldsAppClipDomainStatuses(fieldsAppClipDomainStatuses).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `BuildBundlesApi.BuildBundlesAppClipDomainCacheStatusGetToOneRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `BuildBundlesAppClipDomainCacheStatusGetToOneRelated`: AppClipDomainStatusResponse
    fmt.Fprintf(os.Stdout, "Response from `BuildBundlesApi.BuildBundlesAppClipDomainCacheStatusGetToOneRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiBuildBundlesAppClipDomainCacheStatusGetToOneRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsAppClipDomainStatuses** | **[]string** | the fields to include for returned resources of type appClipDomainStatuses | 

### Return type

[**AppClipDomainStatusResponse**](AppClipDomainStatusResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## BuildBundlesAppClipDomainDebugStatusGetToOneRelated

> AppClipDomainStatusResponse BuildBundlesAppClipDomainDebugStatusGetToOneRelated(ctx, id).FieldsAppClipDomainStatuses(fieldsAppClipDomainStatuses).Execute()



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
    fieldsAppClipDomainStatuses := []string{"FieldsAppClipDomainStatuses_example"} // []string | the fields to include for returned resources of type appClipDomainStatuses (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.BuildBundlesApi.BuildBundlesAppClipDomainDebugStatusGetToOneRelated(context.Background(), id).FieldsAppClipDomainStatuses(fieldsAppClipDomainStatuses).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `BuildBundlesApi.BuildBundlesAppClipDomainDebugStatusGetToOneRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `BuildBundlesAppClipDomainDebugStatusGetToOneRelated`: AppClipDomainStatusResponse
    fmt.Fprintf(os.Stdout, "Response from `BuildBundlesApi.BuildBundlesAppClipDomainDebugStatusGetToOneRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiBuildBundlesAppClipDomainDebugStatusGetToOneRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsAppClipDomainStatuses** | **[]string** | the fields to include for returned resources of type appClipDomainStatuses | 

### Return type

[**AppClipDomainStatusResponse**](AppClipDomainStatusResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## BuildBundlesBetaAppClipInvocationsGetToManyRelated

> BetaAppClipInvocationsResponse BuildBundlesBetaAppClipInvocationsGetToManyRelated(ctx, id).FieldsBetaAppClipInvocations(fieldsBetaAppClipInvocations).FieldsBetaAppClipInvocationLocalizations(fieldsBetaAppClipInvocationLocalizations).Limit(limit).LimitBetaAppClipInvocationLocalizations(limitBetaAppClipInvocationLocalizations).Include(include).Execute()



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
    fieldsBetaAppClipInvocations := []string{"FieldsBetaAppClipInvocations_example"} // []string | the fields to include for returned resources of type betaAppClipInvocations (optional)
    fieldsBetaAppClipInvocationLocalizations := []string{"FieldsBetaAppClipInvocationLocalizations_example"} // []string | the fields to include for returned resources of type betaAppClipInvocationLocalizations (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    limitBetaAppClipInvocationLocalizations := int32(56) // int32 | maximum number of related betaAppClipInvocationLocalizations returned (when they are included) (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.BuildBundlesApi.BuildBundlesBetaAppClipInvocationsGetToManyRelated(context.Background(), id).FieldsBetaAppClipInvocations(fieldsBetaAppClipInvocations).FieldsBetaAppClipInvocationLocalizations(fieldsBetaAppClipInvocationLocalizations).Limit(limit).LimitBetaAppClipInvocationLocalizations(limitBetaAppClipInvocationLocalizations).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `BuildBundlesApi.BuildBundlesBetaAppClipInvocationsGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `BuildBundlesBetaAppClipInvocationsGetToManyRelated`: BetaAppClipInvocationsResponse
    fmt.Fprintf(os.Stdout, "Response from `BuildBundlesApi.BuildBundlesBetaAppClipInvocationsGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiBuildBundlesBetaAppClipInvocationsGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsBetaAppClipInvocations** | **[]string** | the fields to include for returned resources of type betaAppClipInvocations | 
 **fieldsBetaAppClipInvocationLocalizations** | **[]string** | the fields to include for returned resources of type betaAppClipInvocationLocalizations | 
 **limit** | **int32** | maximum resources per page | 
 **limitBetaAppClipInvocationLocalizations** | **int32** | maximum number of related betaAppClipInvocationLocalizations returned (when they are included) | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**BetaAppClipInvocationsResponse**](BetaAppClipInvocationsResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## BuildBundlesBuildBundleFileSizesGetToManyRelated

> BuildBundleFileSizesResponse BuildBundlesBuildBundleFileSizesGetToManyRelated(ctx, id).FieldsBuildBundleFileSizes(fieldsBuildBundleFileSizes).Limit(limit).Execute()



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
    fieldsBuildBundleFileSizes := []string{"FieldsBuildBundleFileSizes_example"} // []string | the fields to include for returned resources of type buildBundleFileSizes (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.BuildBundlesApi.BuildBundlesBuildBundleFileSizesGetToManyRelated(context.Background(), id).FieldsBuildBundleFileSizes(fieldsBuildBundleFileSizes).Limit(limit).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `BuildBundlesApi.BuildBundlesBuildBundleFileSizesGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `BuildBundlesBuildBundleFileSizesGetToManyRelated`: BuildBundleFileSizesResponse
    fmt.Fprintf(os.Stdout, "Response from `BuildBundlesApi.BuildBundlesBuildBundleFileSizesGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiBuildBundlesBuildBundleFileSizesGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsBuildBundleFileSizes** | **[]string** | the fields to include for returned resources of type buildBundleFileSizes | 
 **limit** | **int32** | maximum resources per page | 

### Return type

[**BuildBundleFileSizesResponse**](BuildBundleFileSizesResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

