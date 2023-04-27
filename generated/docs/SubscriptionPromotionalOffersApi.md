# \SubscriptionPromotionalOffersApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**SubscriptionPromotionalOffersCreateInstance**](SubscriptionPromotionalOffersApi.md#SubscriptionPromotionalOffersCreateInstance) | **Post** /v1/subscriptionPromotionalOffers | 
[**SubscriptionPromotionalOffersDeleteInstance**](SubscriptionPromotionalOffersApi.md#SubscriptionPromotionalOffersDeleteInstance) | **Delete** /v1/subscriptionPromotionalOffers/{id} | 
[**SubscriptionPromotionalOffersGetInstance**](SubscriptionPromotionalOffersApi.md#SubscriptionPromotionalOffersGetInstance) | **Get** /v1/subscriptionPromotionalOffers/{id} | 
[**SubscriptionPromotionalOffersPricesGetToManyRelated**](SubscriptionPromotionalOffersApi.md#SubscriptionPromotionalOffersPricesGetToManyRelated) | **Get** /v1/subscriptionPromotionalOffers/{id}/prices | 
[**SubscriptionPromotionalOffersUpdateInstance**](SubscriptionPromotionalOffersApi.md#SubscriptionPromotionalOffersUpdateInstance) | **Patch** /v1/subscriptionPromotionalOffers/{id} | 



## SubscriptionPromotionalOffersCreateInstance

> SubscriptionPromotionalOfferResponse SubscriptionPromotionalOffersCreateInstance(ctx).SubscriptionPromotionalOfferCreateRequest(subscriptionPromotionalOfferCreateRequest).Execute()



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
    subscriptionPromotionalOfferCreateRequest := *openapiclient.NewSubscriptionPromotionalOfferCreateRequest(*openapiclient.NewSubscriptionPromotionalOfferCreateRequestData("Type_example", *openapiclient.NewSubscriptionPromotionalOfferInlineCreateAttributes("Name_example", "OfferCode_example", openapiclient.SubscriptionOfferDuration("ONE_DAY"), openapiclient.SubscriptionOfferMode("PAY_AS_YOU_GO"), int32(123)), *openapiclient.NewSubscriptionPromotionalOfferCreateRequestDataRelationships(*openapiclient.NewSubscriptionAppStoreReviewScreenshotCreateRequestDataRelationshipsSubscription(*openapiclient.NewPromotedPurchaseRelationshipsSubscriptionData("Type_example", "Id_example")), *openapiclient.NewSubscriptionPromotionalOfferCreateRequestDataRelationshipsPrices([]openapiclient.SubscriptionPromotionalOfferRelationshipsPricesDataInner{*openapiclient.NewSubscriptionPromotionalOfferRelationshipsPricesDataInner("Type_example", "Id_example")})))) // SubscriptionPromotionalOfferCreateRequest | SubscriptionPromotionalOffer representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.SubscriptionPromotionalOffersApi.SubscriptionPromotionalOffersCreateInstance(context.Background()).SubscriptionPromotionalOfferCreateRequest(subscriptionPromotionalOfferCreateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `SubscriptionPromotionalOffersApi.SubscriptionPromotionalOffersCreateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `SubscriptionPromotionalOffersCreateInstance`: SubscriptionPromotionalOfferResponse
    fmt.Fprintf(os.Stdout, "Response from `SubscriptionPromotionalOffersApi.SubscriptionPromotionalOffersCreateInstance`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiSubscriptionPromotionalOffersCreateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **subscriptionPromotionalOfferCreateRequest** | [**SubscriptionPromotionalOfferCreateRequest**](SubscriptionPromotionalOfferCreateRequest.md) | SubscriptionPromotionalOffer representation | 

### Return type

[**SubscriptionPromotionalOfferResponse**](SubscriptionPromotionalOfferResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## SubscriptionPromotionalOffersDeleteInstance

> SubscriptionPromotionalOffersDeleteInstance(ctx, id).Execute()



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
    r, err := apiClient.SubscriptionPromotionalOffersApi.SubscriptionPromotionalOffersDeleteInstance(context.Background(), id).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `SubscriptionPromotionalOffersApi.SubscriptionPromotionalOffersDeleteInstance``: %v\n", err)
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

Other parameters are passed through a pointer to a apiSubscriptionPromotionalOffersDeleteInstanceRequest struct via the builder pattern


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


## SubscriptionPromotionalOffersGetInstance

> SubscriptionPromotionalOfferResponse SubscriptionPromotionalOffersGetInstance(ctx, id).FieldsSubscriptionPromotionalOffers(fieldsSubscriptionPromotionalOffers).Include(include).FieldsSubscriptionPromotionalOfferPrices(fieldsSubscriptionPromotionalOfferPrices).LimitPrices(limitPrices).Execute()



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
    fieldsSubscriptionPromotionalOffers := []string{"FieldsSubscriptionPromotionalOffers_example"} // []string | the fields to include for returned resources of type subscriptionPromotionalOffers (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)
    fieldsSubscriptionPromotionalOfferPrices := []string{"FieldsSubscriptionPromotionalOfferPrices_example"} // []string | the fields to include for returned resources of type subscriptionPromotionalOfferPrices (optional)
    limitPrices := int32(56) // int32 | maximum number of related prices returned (when they are included) (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.SubscriptionPromotionalOffersApi.SubscriptionPromotionalOffersGetInstance(context.Background(), id).FieldsSubscriptionPromotionalOffers(fieldsSubscriptionPromotionalOffers).Include(include).FieldsSubscriptionPromotionalOfferPrices(fieldsSubscriptionPromotionalOfferPrices).LimitPrices(limitPrices).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `SubscriptionPromotionalOffersApi.SubscriptionPromotionalOffersGetInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `SubscriptionPromotionalOffersGetInstance`: SubscriptionPromotionalOfferResponse
    fmt.Fprintf(os.Stdout, "Response from `SubscriptionPromotionalOffersApi.SubscriptionPromotionalOffersGetInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiSubscriptionPromotionalOffersGetInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsSubscriptionPromotionalOffers** | **[]string** | the fields to include for returned resources of type subscriptionPromotionalOffers | 
 **include** | **[]string** | comma-separated list of relationships to include | 
 **fieldsSubscriptionPromotionalOfferPrices** | **[]string** | the fields to include for returned resources of type subscriptionPromotionalOfferPrices | 
 **limitPrices** | **int32** | maximum number of related prices returned (when they are included) | 

### Return type

[**SubscriptionPromotionalOfferResponse**](SubscriptionPromotionalOfferResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## SubscriptionPromotionalOffersPricesGetToManyRelated

> SubscriptionPromotionalOfferPricesResponse SubscriptionPromotionalOffersPricesGetToManyRelated(ctx, id).FilterTerritory(filterTerritory).FieldsSubscriptionPricePoints(fieldsSubscriptionPricePoints).FieldsTerritories(fieldsTerritories).FieldsSubscriptionPromotionalOfferPrices(fieldsSubscriptionPromotionalOfferPrices).Limit(limit).Include(include).Execute()



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
    fieldsSubscriptionPricePoints := []string{"FieldsSubscriptionPricePoints_example"} // []string | the fields to include for returned resources of type subscriptionPricePoints (optional)
    fieldsTerritories := []string{"FieldsTerritories_example"} // []string | the fields to include for returned resources of type territories (optional)
    fieldsSubscriptionPromotionalOfferPrices := []string{"FieldsSubscriptionPromotionalOfferPrices_example"} // []string | the fields to include for returned resources of type subscriptionPromotionalOfferPrices (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.SubscriptionPromotionalOffersApi.SubscriptionPromotionalOffersPricesGetToManyRelated(context.Background(), id).FilterTerritory(filterTerritory).FieldsSubscriptionPricePoints(fieldsSubscriptionPricePoints).FieldsTerritories(fieldsTerritories).FieldsSubscriptionPromotionalOfferPrices(fieldsSubscriptionPromotionalOfferPrices).Limit(limit).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `SubscriptionPromotionalOffersApi.SubscriptionPromotionalOffersPricesGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `SubscriptionPromotionalOffersPricesGetToManyRelated`: SubscriptionPromotionalOfferPricesResponse
    fmt.Fprintf(os.Stdout, "Response from `SubscriptionPromotionalOffersApi.SubscriptionPromotionalOffersPricesGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiSubscriptionPromotionalOffersPricesGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **filterTerritory** | **[]string** | filter by id(s) of related &#39;territory&#39; | 
 **fieldsSubscriptionPricePoints** | **[]string** | the fields to include for returned resources of type subscriptionPricePoints | 
 **fieldsTerritories** | **[]string** | the fields to include for returned resources of type territories | 
 **fieldsSubscriptionPromotionalOfferPrices** | **[]string** | the fields to include for returned resources of type subscriptionPromotionalOfferPrices | 
 **limit** | **int32** | maximum resources per page | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**SubscriptionPromotionalOfferPricesResponse**](SubscriptionPromotionalOfferPricesResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## SubscriptionPromotionalOffersUpdateInstance

> SubscriptionPromotionalOfferResponse SubscriptionPromotionalOffersUpdateInstance(ctx, id).SubscriptionPromotionalOfferUpdateRequest(subscriptionPromotionalOfferUpdateRequest).Execute()



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
    subscriptionPromotionalOfferUpdateRequest := *openapiclient.NewSubscriptionPromotionalOfferUpdateRequest(*openapiclient.NewSubscriptionPromotionalOfferUpdateRequestData("Type_example", "Id_example")) // SubscriptionPromotionalOfferUpdateRequest | SubscriptionPromotionalOffer representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.SubscriptionPromotionalOffersApi.SubscriptionPromotionalOffersUpdateInstance(context.Background(), id).SubscriptionPromotionalOfferUpdateRequest(subscriptionPromotionalOfferUpdateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `SubscriptionPromotionalOffersApi.SubscriptionPromotionalOffersUpdateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `SubscriptionPromotionalOffersUpdateInstance`: SubscriptionPromotionalOfferResponse
    fmt.Fprintf(os.Stdout, "Response from `SubscriptionPromotionalOffersApi.SubscriptionPromotionalOffersUpdateInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiSubscriptionPromotionalOffersUpdateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **subscriptionPromotionalOfferUpdateRequest** | [**SubscriptionPromotionalOfferUpdateRequest**](SubscriptionPromotionalOfferUpdateRequest.md) | SubscriptionPromotionalOffer representation | 

### Return type

[**SubscriptionPromotionalOfferResponse**](SubscriptionPromotionalOfferResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

