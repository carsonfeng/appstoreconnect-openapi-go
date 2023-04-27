# \SubscriptionIntroductoryOffersApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**SubscriptionIntroductoryOffersCreateInstance**](SubscriptionIntroductoryOffersApi.md#SubscriptionIntroductoryOffersCreateInstance) | **Post** /v1/subscriptionIntroductoryOffers | 
[**SubscriptionIntroductoryOffersDeleteInstance**](SubscriptionIntroductoryOffersApi.md#SubscriptionIntroductoryOffersDeleteInstance) | **Delete** /v1/subscriptionIntroductoryOffers/{id} | 
[**SubscriptionIntroductoryOffersUpdateInstance**](SubscriptionIntroductoryOffersApi.md#SubscriptionIntroductoryOffersUpdateInstance) | **Patch** /v1/subscriptionIntroductoryOffers/{id} | 



## SubscriptionIntroductoryOffersCreateInstance

> SubscriptionIntroductoryOfferResponse SubscriptionIntroductoryOffersCreateInstance(ctx).SubscriptionIntroductoryOfferCreateRequest(subscriptionIntroductoryOfferCreateRequest).Execute()



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
    subscriptionIntroductoryOfferCreateRequest := *openapiclient.NewSubscriptionIntroductoryOfferCreateRequest(*openapiclient.NewSubscriptionIntroductoryOfferCreateRequestData("Type_example", *openapiclient.NewSubscriptionIntroductoryOfferInlineCreateAttributes(openapiclient.SubscriptionOfferDuration("ONE_DAY"), openapiclient.SubscriptionOfferMode("PAY_AS_YOU_GO"), int32(123)), *openapiclient.NewSubscriptionIntroductoryOfferCreateRequestDataRelationships(*openapiclient.NewSubscriptionAppStoreReviewScreenshotCreateRequestDataRelationshipsSubscription(*openapiclient.NewPromotedPurchaseRelationshipsSubscriptionData("Type_example", "Id_example"))))) // SubscriptionIntroductoryOfferCreateRequest | SubscriptionIntroductoryOffer representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.SubscriptionIntroductoryOffersApi.SubscriptionIntroductoryOffersCreateInstance(context.Background()).SubscriptionIntroductoryOfferCreateRequest(subscriptionIntroductoryOfferCreateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `SubscriptionIntroductoryOffersApi.SubscriptionIntroductoryOffersCreateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `SubscriptionIntroductoryOffersCreateInstance`: SubscriptionIntroductoryOfferResponse
    fmt.Fprintf(os.Stdout, "Response from `SubscriptionIntroductoryOffersApi.SubscriptionIntroductoryOffersCreateInstance`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiSubscriptionIntroductoryOffersCreateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **subscriptionIntroductoryOfferCreateRequest** | [**SubscriptionIntroductoryOfferCreateRequest**](SubscriptionIntroductoryOfferCreateRequest.md) | SubscriptionIntroductoryOffer representation | 

### Return type

[**SubscriptionIntroductoryOfferResponse**](SubscriptionIntroductoryOfferResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## SubscriptionIntroductoryOffersDeleteInstance

> SubscriptionIntroductoryOffersDeleteInstance(ctx, id).Execute()



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
    r, err := apiClient.SubscriptionIntroductoryOffersApi.SubscriptionIntroductoryOffersDeleteInstance(context.Background(), id).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `SubscriptionIntroductoryOffersApi.SubscriptionIntroductoryOffersDeleteInstance``: %v\n", err)
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

Other parameters are passed through a pointer to a apiSubscriptionIntroductoryOffersDeleteInstanceRequest struct via the builder pattern


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


## SubscriptionIntroductoryOffersUpdateInstance

> SubscriptionIntroductoryOfferResponse SubscriptionIntroductoryOffersUpdateInstance(ctx, id).SubscriptionIntroductoryOfferUpdateRequest(subscriptionIntroductoryOfferUpdateRequest).Execute()



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
    subscriptionIntroductoryOfferUpdateRequest := *openapiclient.NewSubscriptionIntroductoryOfferUpdateRequest(*openapiclient.NewSubscriptionIntroductoryOfferUpdateRequestData("Type_example", "Id_example")) // SubscriptionIntroductoryOfferUpdateRequest | SubscriptionIntroductoryOffer representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.SubscriptionIntroductoryOffersApi.SubscriptionIntroductoryOffersUpdateInstance(context.Background(), id).SubscriptionIntroductoryOfferUpdateRequest(subscriptionIntroductoryOfferUpdateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `SubscriptionIntroductoryOffersApi.SubscriptionIntroductoryOffersUpdateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `SubscriptionIntroductoryOffersUpdateInstance`: SubscriptionIntroductoryOfferResponse
    fmt.Fprintf(os.Stdout, "Response from `SubscriptionIntroductoryOffersApi.SubscriptionIntroductoryOffersUpdateInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiSubscriptionIntroductoryOffersUpdateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **subscriptionIntroductoryOfferUpdateRequest** | [**SubscriptionIntroductoryOfferUpdateRequest**](SubscriptionIntroductoryOfferUpdateRequest.md) | SubscriptionIntroductoryOffer representation | 

### Return type

[**SubscriptionIntroductoryOfferResponse**](SubscriptionIntroductoryOfferResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

