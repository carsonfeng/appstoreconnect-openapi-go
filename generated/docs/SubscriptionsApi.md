# \SubscriptionsApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**SubscriptionsAppStoreReviewScreenshotGetToOneRelated**](SubscriptionsApi.md#SubscriptionsAppStoreReviewScreenshotGetToOneRelated) | **Get** /v1/subscriptions/{id}/appStoreReviewScreenshot | 
[**SubscriptionsCreateInstance**](SubscriptionsApi.md#SubscriptionsCreateInstance) | **Post** /v1/subscriptions | 
[**SubscriptionsDeleteInstance**](SubscriptionsApi.md#SubscriptionsDeleteInstance) | **Delete** /v1/subscriptions/{id} | 
[**SubscriptionsGetInstance**](SubscriptionsApi.md#SubscriptionsGetInstance) | **Get** /v1/subscriptions/{id} | 
[**SubscriptionsIntroductoryOffersDeleteToManyRelationship**](SubscriptionsApi.md#SubscriptionsIntroductoryOffersDeleteToManyRelationship) | **Delete** /v1/subscriptions/{id}/relationships/introductoryOffers | 
[**SubscriptionsIntroductoryOffersGetToManyRelated**](SubscriptionsApi.md#SubscriptionsIntroductoryOffersGetToManyRelated) | **Get** /v1/subscriptions/{id}/introductoryOffers | 
[**SubscriptionsIntroductoryOffersGetToManyRelationship**](SubscriptionsApi.md#SubscriptionsIntroductoryOffersGetToManyRelationship) | **Get** /v1/subscriptions/{id}/relationships/introductoryOffers | 
[**SubscriptionsOfferCodesGetToManyRelated**](SubscriptionsApi.md#SubscriptionsOfferCodesGetToManyRelated) | **Get** /v1/subscriptions/{id}/offerCodes | 
[**SubscriptionsPricePointsGetToManyRelated**](SubscriptionsApi.md#SubscriptionsPricePointsGetToManyRelated) | **Get** /v1/subscriptions/{id}/pricePoints | 
[**SubscriptionsPricesDeleteToManyRelationship**](SubscriptionsApi.md#SubscriptionsPricesDeleteToManyRelationship) | **Delete** /v1/subscriptions/{id}/relationships/prices | 
[**SubscriptionsPricesGetToManyRelated**](SubscriptionsApi.md#SubscriptionsPricesGetToManyRelated) | **Get** /v1/subscriptions/{id}/prices | 
[**SubscriptionsPricesGetToManyRelationship**](SubscriptionsApi.md#SubscriptionsPricesGetToManyRelationship) | **Get** /v1/subscriptions/{id}/relationships/prices | 
[**SubscriptionsPromotedPurchaseGetToOneRelated**](SubscriptionsApi.md#SubscriptionsPromotedPurchaseGetToOneRelated) | **Get** /v1/subscriptions/{id}/promotedPurchase | 
[**SubscriptionsPromotionalOffersGetToManyRelated**](SubscriptionsApi.md#SubscriptionsPromotionalOffersGetToManyRelated) | **Get** /v1/subscriptions/{id}/promotionalOffers | 
[**SubscriptionsSubscriptionLocalizationsGetToManyRelated**](SubscriptionsApi.md#SubscriptionsSubscriptionLocalizationsGetToManyRelated) | **Get** /v1/subscriptions/{id}/subscriptionLocalizations | 
[**SubscriptionsUpdateInstance**](SubscriptionsApi.md#SubscriptionsUpdateInstance) | **Patch** /v1/subscriptions/{id} | 



## SubscriptionsAppStoreReviewScreenshotGetToOneRelated

> SubscriptionAppStoreReviewScreenshotResponse SubscriptionsAppStoreReviewScreenshotGetToOneRelated(ctx, id).FieldsSubscriptionAppStoreReviewScreenshots(fieldsSubscriptionAppStoreReviewScreenshots).FieldsSubscriptions(fieldsSubscriptions).Include(include).Execute()



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
    fieldsSubscriptionAppStoreReviewScreenshots := []string{"FieldsSubscriptionAppStoreReviewScreenshots_example"} // []string | the fields to include for returned resources of type subscriptionAppStoreReviewScreenshots (optional)
    fieldsSubscriptions := []string{"FieldsSubscriptions_example"} // []string | the fields to include for returned resources of type subscriptions (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.SubscriptionsApi.SubscriptionsAppStoreReviewScreenshotGetToOneRelated(context.Background(), id).FieldsSubscriptionAppStoreReviewScreenshots(fieldsSubscriptionAppStoreReviewScreenshots).FieldsSubscriptions(fieldsSubscriptions).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `SubscriptionsApi.SubscriptionsAppStoreReviewScreenshotGetToOneRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `SubscriptionsAppStoreReviewScreenshotGetToOneRelated`: SubscriptionAppStoreReviewScreenshotResponse
    fmt.Fprintf(os.Stdout, "Response from `SubscriptionsApi.SubscriptionsAppStoreReviewScreenshotGetToOneRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiSubscriptionsAppStoreReviewScreenshotGetToOneRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsSubscriptionAppStoreReviewScreenshots** | **[]string** | the fields to include for returned resources of type subscriptionAppStoreReviewScreenshots | 
 **fieldsSubscriptions** | **[]string** | the fields to include for returned resources of type subscriptions | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**SubscriptionAppStoreReviewScreenshotResponse**](SubscriptionAppStoreReviewScreenshotResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## SubscriptionsCreateInstance

> SubscriptionResponse SubscriptionsCreateInstance(ctx).SubscriptionCreateRequest(subscriptionCreateRequest).Execute()



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
    subscriptionCreateRequest := *openapiclient.NewSubscriptionCreateRequest(*openapiclient.NewSubscriptionCreateRequestData("Type_example", *openapiclient.NewSubscriptionCreateRequestDataAttributes("Name_example", "ProductId_example"), *openapiclient.NewSubscriptionCreateRequestDataRelationships(*openapiclient.NewSubscriptionGroupLocalizationCreateRequestDataRelationshipsSubscriptionGroup(*openapiclient.NewAppRelationshipsSubscriptionGroupsDataInner("Type_example", "Id_example"))))) // SubscriptionCreateRequest | Subscription representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.SubscriptionsApi.SubscriptionsCreateInstance(context.Background()).SubscriptionCreateRequest(subscriptionCreateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `SubscriptionsApi.SubscriptionsCreateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `SubscriptionsCreateInstance`: SubscriptionResponse
    fmt.Fprintf(os.Stdout, "Response from `SubscriptionsApi.SubscriptionsCreateInstance`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiSubscriptionsCreateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **subscriptionCreateRequest** | [**SubscriptionCreateRequest**](SubscriptionCreateRequest.md) | Subscription representation | 

### Return type

[**SubscriptionResponse**](SubscriptionResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## SubscriptionsDeleteInstance

> SubscriptionsDeleteInstance(ctx, id).Execute()



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
    r, err := apiClient.SubscriptionsApi.SubscriptionsDeleteInstance(context.Background(), id).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `SubscriptionsApi.SubscriptionsDeleteInstance``: %v\n", err)
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

Other parameters are passed through a pointer to a apiSubscriptionsDeleteInstanceRequest struct via the builder pattern


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


## SubscriptionsGetInstance

> SubscriptionResponse SubscriptionsGetInstance(ctx, id).FieldsSubscriptions(fieldsSubscriptions).Include(include).FieldsPromotedPurchases(fieldsPromotedPurchases).FieldsSubscriptionPricePoints(fieldsSubscriptionPricePoints).FieldsSubscriptionPromotionalOffers(fieldsSubscriptionPromotionalOffers).FieldsSubscriptionOfferCodes(fieldsSubscriptionOfferCodes).FieldsSubscriptionAppStoreReviewScreenshots(fieldsSubscriptionAppStoreReviewScreenshots).FieldsSubscriptionPrices(fieldsSubscriptionPrices).FieldsSubscriptionIntroductoryOffers(fieldsSubscriptionIntroductoryOffers).FieldsSubscriptionLocalizations(fieldsSubscriptionLocalizations).LimitIntroductoryOffers(limitIntroductoryOffers).LimitOfferCodes(limitOfferCodes).LimitPrices(limitPrices).LimitPromotionalOffers(limitPromotionalOffers).LimitSubscriptionLocalizations(limitSubscriptionLocalizations).Execute()



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
    fieldsSubscriptions := []string{"FieldsSubscriptions_example"} // []string | the fields to include for returned resources of type subscriptions (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)
    fieldsPromotedPurchases := []string{"FieldsPromotedPurchases_example"} // []string | the fields to include for returned resources of type promotedPurchases (optional)
    fieldsSubscriptionPricePoints := []string{"FieldsSubscriptionPricePoints_example"} // []string | the fields to include for returned resources of type subscriptionPricePoints (optional)
    fieldsSubscriptionPromotionalOffers := []string{"FieldsSubscriptionPromotionalOffers_example"} // []string | the fields to include for returned resources of type subscriptionPromotionalOffers (optional)
    fieldsSubscriptionOfferCodes := []string{"FieldsSubscriptionOfferCodes_example"} // []string | the fields to include for returned resources of type subscriptionOfferCodes (optional)
    fieldsSubscriptionAppStoreReviewScreenshots := []string{"FieldsSubscriptionAppStoreReviewScreenshots_example"} // []string | the fields to include for returned resources of type subscriptionAppStoreReviewScreenshots (optional)
    fieldsSubscriptionPrices := []string{"FieldsSubscriptionPrices_example"} // []string | the fields to include for returned resources of type subscriptionPrices (optional)
    fieldsSubscriptionIntroductoryOffers := []string{"FieldsSubscriptionIntroductoryOffers_example"} // []string | the fields to include for returned resources of type subscriptionIntroductoryOffers (optional)
    fieldsSubscriptionLocalizations := []string{"FieldsSubscriptionLocalizations_example"} // []string | the fields to include for returned resources of type subscriptionLocalizations (optional)
    limitIntroductoryOffers := int32(56) // int32 | maximum number of related introductoryOffers returned (when they are included) (optional)
    limitOfferCodes := int32(56) // int32 | maximum number of related offerCodes returned (when they are included) (optional)
    limitPrices := int32(56) // int32 | maximum number of related prices returned (when they are included) (optional)
    limitPromotionalOffers := int32(56) // int32 | maximum number of related promotionalOffers returned (when they are included) (optional)
    limitSubscriptionLocalizations := int32(56) // int32 | maximum number of related subscriptionLocalizations returned (when they are included) (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.SubscriptionsApi.SubscriptionsGetInstance(context.Background(), id).FieldsSubscriptions(fieldsSubscriptions).Include(include).FieldsPromotedPurchases(fieldsPromotedPurchases).FieldsSubscriptionPricePoints(fieldsSubscriptionPricePoints).FieldsSubscriptionPromotionalOffers(fieldsSubscriptionPromotionalOffers).FieldsSubscriptionOfferCodes(fieldsSubscriptionOfferCodes).FieldsSubscriptionAppStoreReviewScreenshots(fieldsSubscriptionAppStoreReviewScreenshots).FieldsSubscriptionPrices(fieldsSubscriptionPrices).FieldsSubscriptionIntroductoryOffers(fieldsSubscriptionIntroductoryOffers).FieldsSubscriptionLocalizations(fieldsSubscriptionLocalizations).LimitIntroductoryOffers(limitIntroductoryOffers).LimitOfferCodes(limitOfferCodes).LimitPrices(limitPrices).LimitPromotionalOffers(limitPromotionalOffers).LimitSubscriptionLocalizations(limitSubscriptionLocalizations).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `SubscriptionsApi.SubscriptionsGetInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `SubscriptionsGetInstance`: SubscriptionResponse
    fmt.Fprintf(os.Stdout, "Response from `SubscriptionsApi.SubscriptionsGetInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiSubscriptionsGetInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsSubscriptions** | **[]string** | the fields to include for returned resources of type subscriptions | 
 **include** | **[]string** | comma-separated list of relationships to include | 
 **fieldsPromotedPurchases** | **[]string** | the fields to include for returned resources of type promotedPurchases | 
 **fieldsSubscriptionPricePoints** | **[]string** | the fields to include for returned resources of type subscriptionPricePoints | 
 **fieldsSubscriptionPromotionalOffers** | **[]string** | the fields to include for returned resources of type subscriptionPromotionalOffers | 
 **fieldsSubscriptionOfferCodes** | **[]string** | the fields to include for returned resources of type subscriptionOfferCodes | 
 **fieldsSubscriptionAppStoreReviewScreenshots** | **[]string** | the fields to include for returned resources of type subscriptionAppStoreReviewScreenshots | 
 **fieldsSubscriptionPrices** | **[]string** | the fields to include for returned resources of type subscriptionPrices | 
 **fieldsSubscriptionIntroductoryOffers** | **[]string** | the fields to include for returned resources of type subscriptionIntroductoryOffers | 
 **fieldsSubscriptionLocalizations** | **[]string** | the fields to include for returned resources of type subscriptionLocalizations | 
 **limitIntroductoryOffers** | **int32** | maximum number of related introductoryOffers returned (when they are included) | 
 **limitOfferCodes** | **int32** | maximum number of related offerCodes returned (when they are included) | 
 **limitPrices** | **int32** | maximum number of related prices returned (when they are included) | 
 **limitPromotionalOffers** | **int32** | maximum number of related promotionalOffers returned (when they are included) | 
 **limitSubscriptionLocalizations** | **int32** | maximum number of related subscriptionLocalizations returned (when they are included) | 

### Return type

[**SubscriptionResponse**](SubscriptionResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## SubscriptionsIntroductoryOffersDeleteToManyRelationship

> SubscriptionsIntroductoryOffersDeleteToManyRelationship(ctx, id).SubscriptionIntroductoryOffersLinkagesRequest(subscriptionIntroductoryOffersLinkagesRequest).Execute()



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
    subscriptionIntroductoryOffersLinkagesRequest := *openapiclient.NewSubscriptionIntroductoryOffersLinkagesRequest([]openapiclient.SubscriptionRelationshipsIntroductoryOffersDataInner{*openapiclient.NewSubscriptionRelationshipsIntroductoryOffersDataInner("Type_example", "Id_example")}) // SubscriptionIntroductoryOffersLinkagesRequest | List of related linkages

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    r, err := apiClient.SubscriptionsApi.SubscriptionsIntroductoryOffersDeleteToManyRelationship(context.Background(), id).SubscriptionIntroductoryOffersLinkagesRequest(subscriptionIntroductoryOffersLinkagesRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `SubscriptionsApi.SubscriptionsIntroductoryOffersDeleteToManyRelationship``: %v\n", err)
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

Other parameters are passed through a pointer to a apiSubscriptionsIntroductoryOffersDeleteToManyRelationshipRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **subscriptionIntroductoryOffersLinkagesRequest** | [**SubscriptionIntroductoryOffersLinkagesRequest**](SubscriptionIntroductoryOffersLinkagesRequest.md) | List of related linkages | 

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


## SubscriptionsIntroductoryOffersGetToManyRelated

> SubscriptionIntroductoryOffersResponse SubscriptionsIntroductoryOffersGetToManyRelated(ctx, id).FilterTerritory(filterTerritory).FieldsSubscriptionPricePoints(fieldsSubscriptionPricePoints).FieldsSubscriptions(fieldsSubscriptions).FieldsSubscriptionIntroductoryOffers(fieldsSubscriptionIntroductoryOffers).FieldsTerritories(fieldsTerritories).Limit(limit).Include(include).Execute()



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
    fieldsSubscriptions := []string{"FieldsSubscriptions_example"} // []string | the fields to include for returned resources of type subscriptions (optional)
    fieldsSubscriptionIntroductoryOffers := []string{"FieldsSubscriptionIntroductoryOffers_example"} // []string | the fields to include for returned resources of type subscriptionIntroductoryOffers (optional)
    fieldsTerritories := []string{"FieldsTerritories_example"} // []string | the fields to include for returned resources of type territories (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.SubscriptionsApi.SubscriptionsIntroductoryOffersGetToManyRelated(context.Background(), id).FilterTerritory(filterTerritory).FieldsSubscriptionPricePoints(fieldsSubscriptionPricePoints).FieldsSubscriptions(fieldsSubscriptions).FieldsSubscriptionIntroductoryOffers(fieldsSubscriptionIntroductoryOffers).FieldsTerritories(fieldsTerritories).Limit(limit).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `SubscriptionsApi.SubscriptionsIntroductoryOffersGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `SubscriptionsIntroductoryOffersGetToManyRelated`: SubscriptionIntroductoryOffersResponse
    fmt.Fprintf(os.Stdout, "Response from `SubscriptionsApi.SubscriptionsIntroductoryOffersGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiSubscriptionsIntroductoryOffersGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **filterTerritory** | **[]string** | filter by id(s) of related &#39;territory&#39; | 
 **fieldsSubscriptionPricePoints** | **[]string** | the fields to include for returned resources of type subscriptionPricePoints | 
 **fieldsSubscriptions** | **[]string** | the fields to include for returned resources of type subscriptions | 
 **fieldsSubscriptionIntroductoryOffers** | **[]string** | the fields to include for returned resources of type subscriptionIntroductoryOffers | 
 **fieldsTerritories** | **[]string** | the fields to include for returned resources of type territories | 
 **limit** | **int32** | maximum resources per page | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**SubscriptionIntroductoryOffersResponse**](SubscriptionIntroductoryOffersResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## SubscriptionsIntroductoryOffersGetToManyRelationship

> SubscriptionIntroductoryOffersLinkagesResponse SubscriptionsIntroductoryOffersGetToManyRelationship(ctx, id).Limit(limit).Execute()



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
    resp, r, err := apiClient.SubscriptionsApi.SubscriptionsIntroductoryOffersGetToManyRelationship(context.Background(), id).Limit(limit).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `SubscriptionsApi.SubscriptionsIntroductoryOffersGetToManyRelationship``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `SubscriptionsIntroductoryOffersGetToManyRelationship`: SubscriptionIntroductoryOffersLinkagesResponse
    fmt.Fprintf(os.Stdout, "Response from `SubscriptionsApi.SubscriptionsIntroductoryOffersGetToManyRelationship`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiSubscriptionsIntroductoryOffersGetToManyRelationshipRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **limit** | **int32** | maximum resources per page | 

### Return type

[**SubscriptionIntroductoryOffersLinkagesResponse**](SubscriptionIntroductoryOffersLinkagesResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## SubscriptionsOfferCodesGetToManyRelated

> SubscriptionOfferCodesResponse SubscriptionsOfferCodesGetToManyRelated(ctx, id).FilterTerritory(filterTerritory).FieldsSubscriptionOfferCodeCustomCodes(fieldsSubscriptionOfferCodeCustomCodes).FieldsSubscriptionOfferCodes(fieldsSubscriptionOfferCodes).FieldsSubscriptionOfferCodeOneTimeUseCodes(fieldsSubscriptionOfferCodeOneTimeUseCodes).FieldsSubscriptions(fieldsSubscriptions).FieldsSubscriptionOfferCodePrices(fieldsSubscriptionOfferCodePrices).Limit(limit).LimitOneTimeUseCodes(limitOneTimeUseCodes).LimitCustomCodes(limitCustomCodes).LimitPrices(limitPrices).Include(include).Execute()



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
    filterTerritory := []string{"Inner_example"} // []string | filter by territory (optional)
    fieldsSubscriptionOfferCodeCustomCodes := []string{"FieldsSubscriptionOfferCodeCustomCodes_example"} // []string | the fields to include for returned resources of type subscriptionOfferCodeCustomCodes (optional)
    fieldsSubscriptionOfferCodes := []string{"FieldsSubscriptionOfferCodes_example"} // []string | the fields to include for returned resources of type subscriptionOfferCodes (optional)
    fieldsSubscriptionOfferCodeOneTimeUseCodes := []string{"FieldsSubscriptionOfferCodeOneTimeUseCodes_example"} // []string | the fields to include for returned resources of type subscriptionOfferCodeOneTimeUseCodes (optional)
    fieldsSubscriptions := []string{"FieldsSubscriptions_example"} // []string | the fields to include for returned resources of type subscriptions (optional)
    fieldsSubscriptionOfferCodePrices := []string{"FieldsSubscriptionOfferCodePrices_example"} // []string | the fields to include for returned resources of type subscriptionOfferCodePrices (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    limitOneTimeUseCodes := int32(56) // int32 | maximum number of related oneTimeUseCodes returned (when they are included) (optional)
    limitCustomCodes := int32(56) // int32 | maximum number of related customCodes returned (when they are included) (optional)
    limitPrices := int32(56) // int32 | maximum number of related prices returned (when they are included) (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.SubscriptionsApi.SubscriptionsOfferCodesGetToManyRelated(context.Background(), id).FilterTerritory(filterTerritory).FieldsSubscriptionOfferCodeCustomCodes(fieldsSubscriptionOfferCodeCustomCodes).FieldsSubscriptionOfferCodes(fieldsSubscriptionOfferCodes).FieldsSubscriptionOfferCodeOneTimeUseCodes(fieldsSubscriptionOfferCodeOneTimeUseCodes).FieldsSubscriptions(fieldsSubscriptions).FieldsSubscriptionOfferCodePrices(fieldsSubscriptionOfferCodePrices).Limit(limit).LimitOneTimeUseCodes(limitOneTimeUseCodes).LimitCustomCodes(limitCustomCodes).LimitPrices(limitPrices).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `SubscriptionsApi.SubscriptionsOfferCodesGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `SubscriptionsOfferCodesGetToManyRelated`: SubscriptionOfferCodesResponse
    fmt.Fprintf(os.Stdout, "Response from `SubscriptionsApi.SubscriptionsOfferCodesGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiSubscriptionsOfferCodesGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **filterTerritory** | **[]string** | filter by territory | 
 **fieldsSubscriptionOfferCodeCustomCodes** | **[]string** | the fields to include for returned resources of type subscriptionOfferCodeCustomCodes | 
 **fieldsSubscriptionOfferCodes** | **[]string** | the fields to include for returned resources of type subscriptionOfferCodes | 
 **fieldsSubscriptionOfferCodeOneTimeUseCodes** | **[]string** | the fields to include for returned resources of type subscriptionOfferCodeOneTimeUseCodes | 
 **fieldsSubscriptions** | **[]string** | the fields to include for returned resources of type subscriptions | 
 **fieldsSubscriptionOfferCodePrices** | **[]string** | the fields to include for returned resources of type subscriptionOfferCodePrices | 
 **limit** | **int32** | maximum resources per page | 
 **limitOneTimeUseCodes** | **int32** | maximum number of related oneTimeUseCodes returned (when they are included) | 
 **limitCustomCodes** | **int32** | maximum number of related customCodes returned (when they are included) | 
 **limitPrices** | **int32** | maximum number of related prices returned (when they are included) | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**SubscriptionOfferCodesResponse**](SubscriptionOfferCodesResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## SubscriptionsPricePointsGetToManyRelated

> SubscriptionPricePointsResponse SubscriptionsPricePointsGetToManyRelated(ctx, id).FilterTerritory(filterTerritory).FieldsSubscriptionPricePoints(fieldsSubscriptionPricePoints).FieldsTerritories(fieldsTerritories).Limit(limit).Include(include).Execute()



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
    limit := int32(56) // int32 | maximum resources per page (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.SubscriptionsApi.SubscriptionsPricePointsGetToManyRelated(context.Background(), id).FilterTerritory(filterTerritory).FieldsSubscriptionPricePoints(fieldsSubscriptionPricePoints).FieldsTerritories(fieldsTerritories).Limit(limit).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `SubscriptionsApi.SubscriptionsPricePointsGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `SubscriptionsPricePointsGetToManyRelated`: SubscriptionPricePointsResponse
    fmt.Fprintf(os.Stdout, "Response from `SubscriptionsApi.SubscriptionsPricePointsGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiSubscriptionsPricePointsGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **filterTerritory** | **[]string** | filter by id(s) of related &#39;territory&#39; | 
 **fieldsSubscriptionPricePoints** | **[]string** | the fields to include for returned resources of type subscriptionPricePoints | 
 **fieldsTerritories** | **[]string** | the fields to include for returned resources of type territories | 
 **limit** | **int32** | maximum resources per page | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**SubscriptionPricePointsResponse**](SubscriptionPricePointsResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json, text/csv

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## SubscriptionsPricesDeleteToManyRelationship

> SubscriptionsPricesDeleteToManyRelationship(ctx, id).SubscriptionPricesLinkagesRequest(subscriptionPricesLinkagesRequest).Execute()



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
    subscriptionPricesLinkagesRequest := *openapiclient.NewSubscriptionPricesLinkagesRequest([]openapiclient.SubscriptionRelationshipsPricesDataInner{*openapiclient.NewSubscriptionRelationshipsPricesDataInner("Type_example", "Id_example")}) // SubscriptionPricesLinkagesRequest | List of related linkages

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    r, err := apiClient.SubscriptionsApi.SubscriptionsPricesDeleteToManyRelationship(context.Background(), id).SubscriptionPricesLinkagesRequest(subscriptionPricesLinkagesRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `SubscriptionsApi.SubscriptionsPricesDeleteToManyRelationship``: %v\n", err)
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

Other parameters are passed through a pointer to a apiSubscriptionsPricesDeleteToManyRelationshipRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **subscriptionPricesLinkagesRequest** | [**SubscriptionPricesLinkagesRequest**](SubscriptionPricesLinkagesRequest.md) | List of related linkages | 

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


## SubscriptionsPricesGetToManyRelated

> SubscriptionPricesResponse SubscriptionsPricesGetToManyRelated(ctx, id).FilterSubscriptionPricePoint(filterSubscriptionPricePoint).FilterTerritory(filterTerritory).FieldsSubscriptionPricePoints(fieldsSubscriptionPricePoints).FieldsSubscriptionPrices(fieldsSubscriptionPrices).FieldsTerritories(fieldsTerritories).Limit(limit).Include(include).Execute()



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
    filterSubscriptionPricePoint := []string{"Inner_example"} // []string | filter by id(s) of related 'subscriptionPricePoint' (optional)
    filterTerritory := []string{"Inner_example"} // []string | filter by id(s) of related 'territory' (optional)
    fieldsSubscriptionPricePoints := []string{"FieldsSubscriptionPricePoints_example"} // []string | the fields to include for returned resources of type subscriptionPricePoints (optional)
    fieldsSubscriptionPrices := []string{"FieldsSubscriptionPrices_example"} // []string | the fields to include for returned resources of type subscriptionPrices (optional)
    fieldsTerritories := []string{"FieldsTerritories_example"} // []string | the fields to include for returned resources of type territories (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.SubscriptionsApi.SubscriptionsPricesGetToManyRelated(context.Background(), id).FilterSubscriptionPricePoint(filterSubscriptionPricePoint).FilterTerritory(filterTerritory).FieldsSubscriptionPricePoints(fieldsSubscriptionPricePoints).FieldsSubscriptionPrices(fieldsSubscriptionPrices).FieldsTerritories(fieldsTerritories).Limit(limit).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `SubscriptionsApi.SubscriptionsPricesGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `SubscriptionsPricesGetToManyRelated`: SubscriptionPricesResponse
    fmt.Fprintf(os.Stdout, "Response from `SubscriptionsApi.SubscriptionsPricesGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiSubscriptionsPricesGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **filterSubscriptionPricePoint** | **[]string** | filter by id(s) of related &#39;subscriptionPricePoint&#39; | 
 **filterTerritory** | **[]string** | filter by id(s) of related &#39;territory&#39; | 
 **fieldsSubscriptionPricePoints** | **[]string** | the fields to include for returned resources of type subscriptionPricePoints | 
 **fieldsSubscriptionPrices** | **[]string** | the fields to include for returned resources of type subscriptionPrices | 
 **fieldsTerritories** | **[]string** | the fields to include for returned resources of type territories | 
 **limit** | **int32** | maximum resources per page | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**SubscriptionPricesResponse**](SubscriptionPricesResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## SubscriptionsPricesGetToManyRelationship

> SubscriptionPricesLinkagesResponse SubscriptionsPricesGetToManyRelationship(ctx, id).Limit(limit).Execute()



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
    resp, r, err := apiClient.SubscriptionsApi.SubscriptionsPricesGetToManyRelationship(context.Background(), id).Limit(limit).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `SubscriptionsApi.SubscriptionsPricesGetToManyRelationship``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `SubscriptionsPricesGetToManyRelationship`: SubscriptionPricesLinkagesResponse
    fmt.Fprintf(os.Stdout, "Response from `SubscriptionsApi.SubscriptionsPricesGetToManyRelationship`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiSubscriptionsPricesGetToManyRelationshipRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **limit** | **int32** | maximum resources per page | 

### Return type

[**SubscriptionPricesLinkagesResponse**](SubscriptionPricesLinkagesResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## SubscriptionsPromotedPurchaseGetToOneRelated

> PromotedPurchaseResponse SubscriptionsPromotedPurchaseGetToOneRelated(ctx, id).FieldsPromotedPurchases(fieldsPromotedPurchases).FieldsSubscriptions(fieldsSubscriptions).FieldsInAppPurchases(fieldsInAppPurchases).FieldsPromotedPurchaseImages(fieldsPromotedPurchaseImages).LimitPromotionImages(limitPromotionImages).Include(include).Execute()



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
    limitPromotionImages := int32(56) // int32 | maximum number of related promotionImages returned (when they are included) (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.SubscriptionsApi.SubscriptionsPromotedPurchaseGetToOneRelated(context.Background(), id).FieldsPromotedPurchases(fieldsPromotedPurchases).FieldsSubscriptions(fieldsSubscriptions).FieldsInAppPurchases(fieldsInAppPurchases).FieldsPromotedPurchaseImages(fieldsPromotedPurchaseImages).LimitPromotionImages(limitPromotionImages).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `SubscriptionsApi.SubscriptionsPromotedPurchaseGetToOneRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `SubscriptionsPromotedPurchaseGetToOneRelated`: PromotedPurchaseResponse
    fmt.Fprintf(os.Stdout, "Response from `SubscriptionsApi.SubscriptionsPromotedPurchaseGetToOneRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiSubscriptionsPromotedPurchaseGetToOneRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsPromotedPurchases** | **[]string** | the fields to include for returned resources of type promotedPurchases | 
 **fieldsSubscriptions** | **[]string** | the fields to include for returned resources of type subscriptions | 
 **fieldsInAppPurchases** | **[]string** | the fields to include for returned resources of type inAppPurchases | 
 **fieldsPromotedPurchaseImages** | **[]string** | the fields to include for returned resources of type promotedPurchaseImages | 
 **limitPromotionImages** | **int32** | maximum number of related promotionImages returned (when they are included) | 
 **include** | **[]string** | comma-separated list of relationships to include | 

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


## SubscriptionsPromotionalOffersGetToManyRelated

> SubscriptionPromotionalOffersResponse SubscriptionsPromotionalOffersGetToManyRelated(ctx, id).FilterTerritory(filterTerritory).FieldsSubscriptionPromotionalOffers(fieldsSubscriptionPromotionalOffers).FieldsSubscriptions(fieldsSubscriptions).FieldsSubscriptionPromotionalOfferPrices(fieldsSubscriptionPromotionalOfferPrices).Limit(limit).LimitPrices(limitPrices).Include(include).Execute()



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
    filterTerritory := []string{"Inner_example"} // []string | filter by territory (optional)
    fieldsSubscriptionPromotionalOffers := []string{"FieldsSubscriptionPromotionalOffers_example"} // []string | the fields to include for returned resources of type subscriptionPromotionalOffers (optional)
    fieldsSubscriptions := []string{"FieldsSubscriptions_example"} // []string | the fields to include for returned resources of type subscriptions (optional)
    fieldsSubscriptionPromotionalOfferPrices := []string{"FieldsSubscriptionPromotionalOfferPrices_example"} // []string | the fields to include for returned resources of type subscriptionPromotionalOfferPrices (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    limitPrices := int32(56) // int32 | maximum number of related prices returned (when they are included) (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.SubscriptionsApi.SubscriptionsPromotionalOffersGetToManyRelated(context.Background(), id).FilterTerritory(filterTerritory).FieldsSubscriptionPromotionalOffers(fieldsSubscriptionPromotionalOffers).FieldsSubscriptions(fieldsSubscriptions).FieldsSubscriptionPromotionalOfferPrices(fieldsSubscriptionPromotionalOfferPrices).Limit(limit).LimitPrices(limitPrices).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `SubscriptionsApi.SubscriptionsPromotionalOffersGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `SubscriptionsPromotionalOffersGetToManyRelated`: SubscriptionPromotionalOffersResponse
    fmt.Fprintf(os.Stdout, "Response from `SubscriptionsApi.SubscriptionsPromotionalOffersGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiSubscriptionsPromotionalOffersGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **filterTerritory** | **[]string** | filter by territory | 
 **fieldsSubscriptionPromotionalOffers** | **[]string** | the fields to include for returned resources of type subscriptionPromotionalOffers | 
 **fieldsSubscriptions** | **[]string** | the fields to include for returned resources of type subscriptions | 
 **fieldsSubscriptionPromotionalOfferPrices** | **[]string** | the fields to include for returned resources of type subscriptionPromotionalOfferPrices | 
 **limit** | **int32** | maximum resources per page | 
 **limitPrices** | **int32** | maximum number of related prices returned (when they are included) | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**SubscriptionPromotionalOffersResponse**](SubscriptionPromotionalOffersResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## SubscriptionsSubscriptionLocalizationsGetToManyRelated

> SubscriptionLocalizationsResponse SubscriptionsSubscriptionLocalizationsGetToManyRelated(ctx, id).FieldsSubscriptions(fieldsSubscriptions).FieldsSubscriptionLocalizations(fieldsSubscriptionLocalizations).Limit(limit).Include(include).Execute()



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
    fieldsSubscriptions := []string{"FieldsSubscriptions_example"} // []string | the fields to include for returned resources of type subscriptions (optional)
    fieldsSubscriptionLocalizations := []string{"FieldsSubscriptionLocalizations_example"} // []string | the fields to include for returned resources of type subscriptionLocalizations (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.SubscriptionsApi.SubscriptionsSubscriptionLocalizationsGetToManyRelated(context.Background(), id).FieldsSubscriptions(fieldsSubscriptions).FieldsSubscriptionLocalizations(fieldsSubscriptionLocalizations).Limit(limit).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `SubscriptionsApi.SubscriptionsSubscriptionLocalizationsGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `SubscriptionsSubscriptionLocalizationsGetToManyRelated`: SubscriptionLocalizationsResponse
    fmt.Fprintf(os.Stdout, "Response from `SubscriptionsApi.SubscriptionsSubscriptionLocalizationsGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiSubscriptionsSubscriptionLocalizationsGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsSubscriptions** | **[]string** | the fields to include for returned resources of type subscriptions | 
 **fieldsSubscriptionLocalizations** | **[]string** | the fields to include for returned resources of type subscriptionLocalizations | 
 **limit** | **int32** | maximum resources per page | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**SubscriptionLocalizationsResponse**](SubscriptionLocalizationsResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## SubscriptionsUpdateInstance

> SubscriptionResponse SubscriptionsUpdateInstance(ctx, id).SubscriptionUpdateRequest(subscriptionUpdateRequest).Execute()



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
    subscriptionUpdateRequest := *openapiclient.NewSubscriptionUpdateRequest(*openapiclient.NewSubscriptionUpdateRequestData("Type_example", "Id_example")) // SubscriptionUpdateRequest | Subscription representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.SubscriptionsApi.SubscriptionsUpdateInstance(context.Background(), id).SubscriptionUpdateRequest(subscriptionUpdateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `SubscriptionsApi.SubscriptionsUpdateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `SubscriptionsUpdateInstance`: SubscriptionResponse
    fmt.Fprintf(os.Stdout, "Response from `SubscriptionsApi.SubscriptionsUpdateInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiSubscriptionsUpdateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **subscriptionUpdateRequest** | [**SubscriptionUpdateRequest**](SubscriptionUpdateRequest.md) | Subscription representation | 

### Return type

[**SubscriptionResponse**](SubscriptionResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

