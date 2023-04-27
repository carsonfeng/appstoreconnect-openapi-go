# \PromotedPurchasesApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**PromotedPurchasesCreateInstance**](PromotedPurchasesApi.md#PromotedPurchasesCreateInstance) | **Post** /v1/promotedPurchases | 
[**PromotedPurchasesDeleteInstance**](PromotedPurchasesApi.md#PromotedPurchasesDeleteInstance) | **Delete** /v1/promotedPurchases/{id} | 
[**PromotedPurchasesGetInstance**](PromotedPurchasesApi.md#PromotedPurchasesGetInstance) | **Get** /v1/promotedPurchases/{id} | 
[**PromotedPurchasesPromotionImagesGetToManyRelated**](PromotedPurchasesApi.md#PromotedPurchasesPromotionImagesGetToManyRelated) | **Get** /v1/promotedPurchases/{id}/promotionImages | 
[**PromotedPurchasesUpdateInstance**](PromotedPurchasesApi.md#PromotedPurchasesUpdateInstance) | **Patch** /v1/promotedPurchases/{id} | 



## PromotedPurchasesCreateInstance

> PromotedPurchaseResponse PromotedPurchasesCreateInstance(ctx).PromotedPurchaseCreateRequest(promotedPurchaseCreateRequest).Execute()



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
    promotedPurchaseCreateRequest := *openapiclient.NewPromotedPurchaseCreateRequest(*openapiclient.NewPromotedPurchaseCreateRequestData("Type_example", *openapiclient.NewPromotedPurchaseCreateRequestDataAttributes(false), *openapiclient.NewPromotedPurchaseCreateRequestDataRelationships(*openapiclient.NewAppAvailabilityCreateRequestDataRelationshipsApp(*openapiclient.NewAppAvailabilityRelationshipsAppData("Type_example", "Id_example"))))) // PromotedPurchaseCreateRequest | PromotedPurchase representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.PromotedPurchasesApi.PromotedPurchasesCreateInstance(context.Background()).PromotedPurchaseCreateRequest(promotedPurchaseCreateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `PromotedPurchasesApi.PromotedPurchasesCreateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `PromotedPurchasesCreateInstance`: PromotedPurchaseResponse
    fmt.Fprintf(os.Stdout, "Response from `PromotedPurchasesApi.PromotedPurchasesCreateInstance`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiPromotedPurchasesCreateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **promotedPurchaseCreateRequest** | [**PromotedPurchaseCreateRequest**](PromotedPurchaseCreateRequest.md) | PromotedPurchase representation | 

### Return type

[**PromotedPurchaseResponse**](PromotedPurchaseResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## PromotedPurchasesDeleteInstance

> PromotedPurchasesDeleteInstance(ctx, id).Execute()



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
    r, err := apiClient.PromotedPurchasesApi.PromotedPurchasesDeleteInstance(context.Background(), id).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `PromotedPurchasesApi.PromotedPurchasesDeleteInstance``: %v\n", err)
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

Other parameters are passed through a pointer to a apiPromotedPurchasesDeleteInstanceRequest struct via the builder pattern


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


## PromotedPurchasesGetInstance

> PromotedPurchaseResponse PromotedPurchasesGetInstance(ctx, id).FieldsPromotedPurchases(fieldsPromotedPurchases).Include(include).FieldsPromotedPurchaseImages(fieldsPromotedPurchaseImages).LimitPromotionImages(limitPromotionImages).Execute()



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
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)
    fieldsPromotedPurchaseImages := []string{"FieldsPromotedPurchaseImages_example"} // []string | the fields to include for returned resources of type promotedPurchaseImages (optional)
    limitPromotionImages := int32(56) // int32 | maximum number of related promotionImages returned (when they are included) (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.PromotedPurchasesApi.PromotedPurchasesGetInstance(context.Background(), id).FieldsPromotedPurchases(fieldsPromotedPurchases).Include(include).FieldsPromotedPurchaseImages(fieldsPromotedPurchaseImages).LimitPromotionImages(limitPromotionImages).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `PromotedPurchasesApi.PromotedPurchasesGetInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `PromotedPurchasesGetInstance`: PromotedPurchaseResponse
    fmt.Fprintf(os.Stdout, "Response from `PromotedPurchasesApi.PromotedPurchasesGetInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiPromotedPurchasesGetInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsPromotedPurchases** | **[]string** | the fields to include for returned resources of type promotedPurchases | 
 **include** | **[]string** | comma-separated list of relationships to include | 
 **fieldsPromotedPurchaseImages** | **[]string** | the fields to include for returned resources of type promotedPurchaseImages | 
 **limitPromotionImages** | **int32** | maximum number of related promotionImages returned (when they are included) | 

### Return type

[**PromotedPurchaseResponse**](PromotedPurchaseResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## PromotedPurchasesPromotionImagesGetToManyRelated

> PromotedPurchaseImagesResponse PromotedPurchasesPromotionImagesGetToManyRelated(ctx, id).FieldsPromotedPurchases(fieldsPromotedPurchases).FieldsPromotedPurchaseImages(fieldsPromotedPurchaseImages).Limit(limit).Include(include).Execute()



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
    fieldsPromotedPurchaseImages := []string{"FieldsPromotedPurchaseImages_example"} // []string | the fields to include for returned resources of type promotedPurchaseImages (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.PromotedPurchasesApi.PromotedPurchasesPromotionImagesGetToManyRelated(context.Background(), id).FieldsPromotedPurchases(fieldsPromotedPurchases).FieldsPromotedPurchaseImages(fieldsPromotedPurchaseImages).Limit(limit).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `PromotedPurchasesApi.PromotedPurchasesPromotionImagesGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `PromotedPurchasesPromotionImagesGetToManyRelated`: PromotedPurchaseImagesResponse
    fmt.Fprintf(os.Stdout, "Response from `PromotedPurchasesApi.PromotedPurchasesPromotionImagesGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiPromotedPurchasesPromotionImagesGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsPromotedPurchases** | **[]string** | the fields to include for returned resources of type promotedPurchases | 
 **fieldsPromotedPurchaseImages** | **[]string** | the fields to include for returned resources of type promotedPurchaseImages | 
 **limit** | **int32** | maximum resources per page | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**PromotedPurchaseImagesResponse**](PromotedPurchaseImagesResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## PromotedPurchasesUpdateInstance

> PromotedPurchaseResponse PromotedPurchasesUpdateInstance(ctx, id).PromotedPurchaseUpdateRequest(promotedPurchaseUpdateRequest).Execute()



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
    promotedPurchaseUpdateRequest := *openapiclient.NewPromotedPurchaseUpdateRequest(*openapiclient.NewPromotedPurchaseUpdateRequestData("Type_example", "Id_example")) // PromotedPurchaseUpdateRequest | PromotedPurchase representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.PromotedPurchasesApi.PromotedPurchasesUpdateInstance(context.Background(), id).PromotedPurchaseUpdateRequest(promotedPurchaseUpdateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `PromotedPurchasesApi.PromotedPurchasesUpdateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `PromotedPurchasesUpdateInstance`: PromotedPurchaseResponse
    fmt.Fprintf(os.Stdout, "Response from `PromotedPurchasesApi.PromotedPurchasesUpdateInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiPromotedPurchasesUpdateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **promotedPurchaseUpdateRequest** | [**PromotedPurchaseUpdateRequest**](PromotedPurchaseUpdateRequest.md) | PromotedPurchase representation | 

### Return type

[**PromotedPurchaseResponse**](PromotedPurchaseResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

