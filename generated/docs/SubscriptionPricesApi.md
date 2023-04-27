# \SubscriptionPricesApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**SubscriptionPricesCreateInstance**](SubscriptionPricesApi.md#SubscriptionPricesCreateInstance) | **Post** /v1/subscriptionPrices | 
[**SubscriptionPricesDeleteInstance**](SubscriptionPricesApi.md#SubscriptionPricesDeleteInstance) | **Delete** /v1/subscriptionPrices/{id} | 



## SubscriptionPricesCreateInstance

> SubscriptionPriceResponse SubscriptionPricesCreateInstance(ctx).SubscriptionPriceCreateRequest(subscriptionPriceCreateRequest).Execute()



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
    subscriptionPriceCreateRequest := *openapiclient.NewSubscriptionPriceCreateRequest(*openapiclient.NewSubscriptionPriceCreateRequestData("Type_example", *openapiclient.NewSubscriptionPriceCreateRequestDataRelationships(*openapiclient.NewSubscriptionAppStoreReviewScreenshotCreateRequestDataRelationshipsSubscription(*openapiclient.NewPromotedPurchaseRelationshipsSubscriptionData("Type_example", "Id_example")), *openapiclient.NewSubscriptionPriceCreateRequestDataRelationshipsSubscriptionPricePoint(*openapiclient.NewSubscriptionIntroductoryOfferRelationshipsSubscriptionPricePointData("Type_example", "Id_example"))))) // SubscriptionPriceCreateRequest | SubscriptionPrice representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.SubscriptionPricesApi.SubscriptionPricesCreateInstance(context.Background()).SubscriptionPriceCreateRequest(subscriptionPriceCreateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `SubscriptionPricesApi.SubscriptionPricesCreateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `SubscriptionPricesCreateInstance`: SubscriptionPriceResponse
    fmt.Fprintf(os.Stdout, "Response from `SubscriptionPricesApi.SubscriptionPricesCreateInstance`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiSubscriptionPricesCreateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **subscriptionPriceCreateRequest** | [**SubscriptionPriceCreateRequest**](SubscriptionPriceCreateRequest.md) | SubscriptionPrice representation | 

### Return type

[**SubscriptionPriceResponse**](SubscriptionPriceResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## SubscriptionPricesDeleteInstance

> SubscriptionPricesDeleteInstance(ctx, id).Execute()



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
    r, err := apiClient.SubscriptionPricesApi.SubscriptionPricesDeleteInstance(context.Background(), id).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `SubscriptionPricesApi.SubscriptionPricesDeleteInstance``: %v\n", err)
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

Other parameters are passed through a pointer to a apiSubscriptionPricesDeleteInstanceRequest struct via the builder pattern


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

