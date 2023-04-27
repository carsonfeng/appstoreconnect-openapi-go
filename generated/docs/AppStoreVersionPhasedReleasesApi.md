# \AppStoreVersionPhasedReleasesApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**AppStoreVersionPhasedReleasesCreateInstance**](AppStoreVersionPhasedReleasesApi.md#AppStoreVersionPhasedReleasesCreateInstance) | **Post** /v1/appStoreVersionPhasedReleases | 
[**AppStoreVersionPhasedReleasesDeleteInstance**](AppStoreVersionPhasedReleasesApi.md#AppStoreVersionPhasedReleasesDeleteInstance) | **Delete** /v1/appStoreVersionPhasedReleases/{id} | 
[**AppStoreVersionPhasedReleasesUpdateInstance**](AppStoreVersionPhasedReleasesApi.md#AppStoreVersionPhasedReleasesUpdateInstance) | **Patch** /v1/appStoreVersionPhasedReleases/{id} | 



## AppStoreVersionPhasedReleasesCreateInstance

> AppStoreVersionPhasedReleaseResponse AppStoreVersionPhasedReleasesCreateInstance(ctx).AppStoreVersionPhasedReleaseCreateRequest(appStoreVersionPhasedReleaseCreateRequest).Execute()



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
    appStoreVersionPhasedReleaseCreateRequest := *openapiclient.NewAppStoreVersionPhasedReleaseCreateRequest(*openapiclient.NewAppStoreVersionPhasedReleaseCreateRequestData("Type_example", *openapiclient.NewAppStoreReviewDetailCreateRequestDataRelationships(*openapiclient.NewAppStoreReviewDetailCreateRequestDataRelationshipsAppStoreVersion(*openapiclient.NewAppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersionData("Type_example", "Id_example"))))) // AppStoreVersionPhasedReleaseCreateRequest | AppStoreVersionPhasedRelease representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppStoreVersionPhasedReleasesApi.AppStoreVersionPhasedReleasesCreateInstance(context.Background()).AppStoreVersionPhasedReleaseCreateRequest(appStoreVersionPhasedReleaseCreateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppStoreVersionPhasedReleasesApi.AppStoreVersionPhasedReleasesCreateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppStoreVersionPhasedReleasesCreateInstance`: AppStoreVersionPhasedReleaseResponse
    fmt.Fprintf(os.Stdout, "Response from `AppStoreVersionPhasedReleasesApi.AppStoreVersionPhasedReleasesCreateInstance`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiAppStoreVersionPhasedReleasesCreateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **appStoreVersionPhasedReleaseCreateRequest** | [**AppStoreVersionPhasedReleaseCreateRequest**](AppStoreVersionPhasedReleaseCreateRequest.md) | AppStoreVersionPhasedRelease representation | 

### Return type

[**AppStoreVersionPhasedReleaseResponse**](AppStoreVersionPhasedReleaseResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppStoreVersionPhasedReleasesDeleteInstance

> AppStoreVersionPhasedReleasesDeleteInstance(ctx, id).Execute()



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
    r, err := apiClient.AppStoreVersionPhasedReleasesApi.AppStoreVersionPhasedReleasesDeleteInstance(context.Background(), id).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppStoreVersionPhasedReleasesApi.AppStoreVersionPhasedReleasesDeleteInstance``: %v\n", err)
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

Other parameters are passed through a pointer to a apiAppStoreVersionPhasedReleasesDeleteInstanceRequest struct via the builder pattern


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


## AppStoreVersionPhasedReleasesUpdateInstance

> AppStoreVersionPhasedReleaseResponse AppStoreVersionPhasedReleasesUpdateInstance(ctx, id).AppStoreVersionPhasedReleaseUpdateRequest(appStoreVersionPhasedReleaseUpdateRequest).Execute()



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
    appStoreVersionPhasedReleaseUpdateRequest := *openapiclient.NewAppStoreVersionPhasedReleaseUpdateRequest(*openapiclient.NewAppStoreVersionPhasedReleaseUpdateRequestData("Type_example", "Id_example")) // AppStoreVersionPhasedReleaseUpdateRequest | AppStoreVersionPhasedRelease representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppStoreVersionPhasedReleasesApi.AppStoreVersionPhasedReleasesUpdateInstance(context.Background(), id).AppStoreVersionPhasedReleaseUpdateRequest(appStoreVersionPhasedReleaseUpdateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppStoreVersionPhasedReleasesApi.AppStoreVersionPhasedReleasesUpdateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppStoreVersionPhasedReleasesUpdateInstance`: AppStoreVersionPhasedReleaseResponse
    fmt.Fprintf(os.Stdout, "Response from `AppStoreVersionPhasedReleasesApi.AppStoreVersionPhasedReleasesUpdateInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppStoreVersionPhasedReleasesUpdateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **appStoreVersionPhasedReleaseUpdateRequest** | [**AppStoreVersionPhasedReleaseUpdateRequest**](AppStoreVersionPhasedReleaseUpdateRequest.md) | AppStoreVersionPhasedRelease representation | 

### Return type

[**AppStoreVersionPhasedReleaseResponse**](AppStoreVersionPhasedReleaseResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

