# \InAppPurchaseLocalizationsApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**InAppPurchaseLocalizationsCreateInstance**](InAppPurchaseLocalizationsApi.md#InAppPurchaseLocalizationsCreateInstance) | **Post** /v1/inAppPurchaseLocalizations | 
[**InAppPurchaseLocalizationsDeleteInstance**](InAppPurchaseLocalizationsApi.md#InAppPurchaseLocalizationsDeleteInstance) | **Delete** /v1/inAppPurchaseLocalizations/{id} | 
[**InAppPurchaseLocalizationsGetInstance**](InAppPurchaseLocalizationsApi.md#InAppPurchaseLocalizationsGetInstance) | **Get** /v1/inAppPurchaseLocalizations/{id} | 
[**InAppPurchaseLocalizationsUpdateInstance**](InAppPurchaseLocalizationsApi.md#InAppPurchaseLocalizationsUpdateInstance) | **Patch** /v1/inAppPurchaseLocalizations/{id} | 



## InAppPurchaseLocalizationsCreateInstance

> InAppPurchaseLocalizationResponse InAppPurchaseLocalizationsCreateInstance(ctx).InAppPurchaseLocalizationCreateRequest(inAppPurchaseLocalizationCreateRequest).Execute()



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
    inAppPurchaseLocalizationCreateRequest := *openapiclient.NewInAppPurchaseLocalizationCreateRequest(*openapiclient.NewInAppPurchaseLocalizationCreateRequestData("Type_example", *openapiclient.NewInAppPurchaseLocalizationCreateRequestDataAttributes("Name_example", "Locale_example"), *openapiclient.NewInAppPurchaseAppStoreReviewScreenshotCreateRequestDataRelationships(*openapiclient.NewInAppPurchaseAppStoreReviewScreenshotCreateRequestDataRelationshipsInAppPurchaseV2(*openapiclient.NewAppRelationshipsInAppPurchasesDataInner("Type_example", "Id_example"))))) // InAppPurchaseLocalizationCreateRequest | InAppPurchaseLocalization representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.InAppPurchaseLocalizationsApi.InAppPurchaseLocalizationsCreateInstance(context.Background()).InAppPurchaseLocalizationCreateRequest(inAppPurchaseLocalizationCreateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `InAppPurchaseLocalizationsApi.InAppPurchaseLocalizationsCreateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `InAppPurchaseLocalizationsCreateInstance`: InAppPurchaseLocalizationResponse
    fmt.Fprintf(os.Stdout, "Response from `InAppPurchaseLocalizationsApi.InAppPurchaseLocalizationsCreateInstance`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiInAppPurchaseLocalizationsCreateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **inAppPurchaseLocalizationCreateRequest** | [**InAppPurchaseLocalizationCreateRequest**](InAppPurchaseLocalizationCreateRequest.md) | InAppPurchaseLocalization representation | 

### Return type

[**InAppPurchaseLocalizationResponse**](InAppPurchaseLocalizationResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## InAppPurchaseLocalizationsDeleteInstance

> InAppPurchaseLocalizationsDeleteInstance(ctx, id).Execute()



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
    r, err := apiClient.InAppPurchaseLocalizationsApi.InAppPurchaseLocalizationsDeleteInstance(context.Background(), id).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `InAppPurchaseLocalizationsApi.InAppPurchaseLocalizationsDeleteInstance``: %v\n", err)
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

Other parameters are passed through a pointer to a apiInAppPurchaseLocalizationsDeleteInstanceRequest struct via the builder pattern


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


## InAppPurchaseLocalizationsGetInstance

> InAppPurchaseLocalizationResponse InAppPurchaseLocalizationsGetInstance(ctx, id).FieldsInAppPurchaseLocalizations(fieldsInAppPurchaseLocalizations).Include(include).Execute()



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
    fieldsInAppPurchaseLocalizations := []string{"FieldsInAppPurchaseLocalizations_example"} // []string | the fields to include for returned resources of type inAppPurchaseLocalizations (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.InAppPurchaseLocalizationsApi.InAppPurchaseLocalizationsGetInstance(context.Background(), id).FieldsInAppPurchaseLocalizations(fieldsInAppPurchaseLocalizations).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `InAppPurchaseLocalizationsApi.InAppPurchaseLocalizationsGetInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `InAppPurchaseLocalizationsGetInstance`: InAppPurchaseLocalizationResponse
    fmt.Fprintf(os.Stdout, "Response from `InAppPurchaseLocalizationsApi.InAppPurchaseLocalizationsGetInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiInAppPurchaseLocalizationsGetInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsInAppPurchaseLocalizations** | **[]string** | the fields to include for returned resources of type inAppPurchaseLocalizations | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**InAppPurchaseLocalizationResponse**](InAppPurchaseLocalizationResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## InAppPurchaseLocalizationsUpdateInstance

> InAppPurchaseLocalizationResponse InAppPurchaseLocalizationsUpdateInstance(ctx, id).InAppPurchaseLocalizationUpdateRequest(inAppPurchaseLocalizationUpdateRequest).Execute()



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
    inAppPurchaseLocalizationUpdateRequest := *openapiclient.NewInAppPurchaseLocalizationUpdateRequest(*openapiclient.NewInAppPurchaseLocalizationUpdateRequestData("Type_example", "Id_example")) // InAppPurchaseLocalizationUpdateRequest | InAppPurchaseLocalization representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.InAppPurchaseLocalizationsApi.InAppPurchaseLocalizationsUpdateInstance(context.Background(), id).InAppPurchaseLocalizationUpdateRequest(inAppPurchaseLocalizationUpdateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `InAppPurchaseLocalizationsApi.InAppPurchaseLocalizationsUpdateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `InAppPurchaseLocalizationsUpdateInstance`: InAppPurchaseLocalizationResponse
    fmt.Fprintf(os.Stdout, "Response from `InAppPurchaseLocalizationsApi.InAppPurchaseLocalizationsUpdateInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiInAppPurchaseLocalizationsUpdateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **inAppPurchaseLocalizationUpdateRequest** | [**InAppPurchaseLocalizationUpdateRequest**](InAppPurchaseLocalizationUpdateRequest.md) | InAppPurchaseLocalization representation | 

### Return type

[**InAppPurchaseLocalizationResponse**](InAppPurchaseLocalizationResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

