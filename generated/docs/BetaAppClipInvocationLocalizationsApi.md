# \BetaAppClipInvocationLocalizationsApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**BetaAppClipInvocationLocalizationsCreateInstance**](BetaAppClipInvocationLocalizationsApi.md#BetaAppClipInvocationLocalizationsCreateInstance) | **Post** /v1/betaAppClipInvocationLocalizations | 
[**BetaAppClipInvocationLocalizationsDeleteInstance**](BetaAppClipInvocationLocalizationsApi.md#BetaAppClipInvocationLocalizationsDeleteInstance) | **Delete** /v1/betaAppClipInvocationLocalizations/{id} | 
[**BetaAppClipInvocationLocalizationsUpdateInstance**](BetaAppClipInvocationLocalizationsApi.md#BetaAppClipInvocationLocalizationsUpdateInstance) | **Patch** /v1/betaAppClipInvocationLocalizations/{id} | 



## BetaAppClipInvocationLocalizationsCreateInstance

> BetaAppClipInvocationLocalizationResponse BetaAppClipInvocationLocalizationsCreateInstance(ctx).BetaAppClipInvocationLocalizationCreateRequest(betaAppClipInvocationLocalizationCreateRequest).Execute()



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
    betaAppClipInvocationLocalizationCreateRequest := *openapiclient.NewBetaAppClipInvocationLocalizationCreateRequest(*openapiclient.NewBetaAppClipInvocationLocalizationCreateRequestData("Type_example", *openapiclient.NewBetaAppClipInvocationLocalizationInlineCreateAttributes("Title_example", "Locale_example"), *openapiclient.NewBetaAppClipInvocationLocalizationCreateRequestDataRelationships(*openapiclient.NewBetaAppClipInvocationLocalizationCreateRequestDataRelationshipsBetaAppClipInvocation(*openapiclient.NewBetaAppClipInvocationLocalizationInlineCreateRelationshipsBetaAppClipInvocationData("Type_example", "Id_example"))))) // BetaAppClipInvocationLocalizationCreateRequest | BetaAppClipInvocationLocalization representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.BetaAppClipInvocationLocalizationsApi.BetaAppClipInvocationLocalizationsCreateInstance(context.Background()).BetaAppClipInvocationLocalizationCreateRequest(betaAppClipInvocationLocalizationCreateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `BetaAppClipInvocationLocalizationsApi.BetaAppClipInvocationLocalizationsCreateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `BetaAppClipInvocationLocalizationsCreateInstance`: BetaAppClipInvocationLocalizationResponse
    fmt.Fprintf(os.Stdout, "Response from `BetaAppClipInvocationLocalizationsApi.BetaAppClipInvocationLocalizationsCreateInstance`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiBetaAppClipInvocationLocalizationsCreateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **betaAppClipInvocationLocalizationCreateRequest** | [**BetaAppClipInvocationLocalizationCreateRequest**](BetaAppClipInvocationLocalizationCreateRequest.md) | BetaAppClipInvocationLocalization representation | 

### Return type

[**BetaAppClipInvocationLocalizationResponse**](BetaAppClipInvocationLocalizationResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## BetaAppClipInvocationLocalizationsDeleteInstance

> BetaAppClipInvocationLocalizationsDeleteInstance(ctx, id).Execute()



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
    r, err := apiClient.BetaAppClipInvocationLocalizationsApi.BetaAppClipInvocationLocalizationsDeleteInstance(context.Background(), id).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `BetaAppClipInvocationLocalizationsApi.BetaAppClipInvocationLocalizationsDeleteInstance``: %v\n", err)
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

Other parameters are passed through a pointer to a apiBetaAppClipInvocationLocalizationsDeleteInstanceRequest struct via the builder pattern


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


## BetaAppClipInvocationLocalizationsUpdateInstance

> BetaAppClipInvocationLocalizationResponse BetaAppClipInvocationLocalizationsUpdateInstance(ctx, id).BetaAppClipInvocationLocalizationUpdateRequest(betaAppClipInvocationLocalizationUpdateRequest).Execute()



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
    betaAppClipInvocationLocalizationUpdateRequest := *openapiclient.NewBetaAppClipInvocationLocalizationUpdateRequest(*openapiclient.NewBetaAppClipInvocationLocalizationUpdateRequestData("Type_example", "Id_example")) // BetaAppClipInvocationLocalizationUpdateRequest | BetaAppClipInvocationLocalization representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.BetaAppClipInvocationLocalizationsApi.BetaAppClipInvocationLocalizationsUpdateInstance(context.Background(), id).BetaAppClipInvocationLocalizationUpdateRequest(betaAppClipInvocationLocalizationUpdateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `BetaAppClipInvocationLocalizationsApi.BetaAppClipInvocationLocalizationsUpdateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `BetaAppClipInvocationLocalizationsUpdateInstance`: BetaAppClipInvocationLocalizationResponse
    fmt.Fprintf(os.Stdout, "Response from `BetaAppClipInvocationLocalizationsApi.BetaAppClipInvocationLocalizationsUpdateInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiBetaAppClipInvocationLocalizationsUpdateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **betaAppClipInvocationLocalizationUpdateRequest** | [**BetaAppClipInvocationLocalizationUpdateRequest**](BetaAppClipInvocationLocalizationUpdateRequest.md) | BetaAppClipInvocationLocalization representation | 

### Return type

[**BetaAppClipInvocationLocalizationResponse**](BetaAppClipInvocationLocalizationResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

