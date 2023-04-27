# \SubscriptionGroupsApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**SubscriptionGroupsCreateInstance**](SubscriptionGroupsApi.md#SubscriptionGroupsCreateInstance) | **Post** /v1/subscriptionGroups | 
[**SubscriptionGroupsDeleteInstance**](SubscriptionGroupsApi.md#SubscriptionGroupsDeleteInstance) | **Delete** /v1/subscriptionGroups/{id} | 
[**SubscriptionGroupsGetInstance**](SubscriptionGroupsApi.md#SubscriptionGroupsGetInstance) | **Get** /v1/subscriptionGroups/{id} | 
[**SubscriptionGroupsSubscriptionGroupLocalizationsGetToManyRelated**](SubscriptionGroupsApi.md#SubscriptionGroupsSubscriptionGroupLocalizationsGetToManyRelated) | **Get** /v1/subscriptionGroups/{id}/subscriptionGroupLocalizations | 
[**SubscriptionGroupsSubscriptionsGetToManyRelated**](SubscriptionGroupsApi.md#SubscriptionGroupsSubscriptionsGetToManyRelated) | **Get** /v1/subscriptionGroups/{id}/subscriptions | 
[**SubscriptionGroupsUpdateInstance**](SubscriptionGroupsApi.md#SubscriptionGroupsUpdateInstance) | **Patch** /v1/subscriptionGroups/{id} | 



## SubscriptionGroupsCreateInstance

> SubscriptionGroupResponse SubscriptionGroupsCreateInstance(ctx).SubscriptionGroupCreateRequest(subscriptionGroupCreateRequest).Execute()



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
    subscriptionGroupCreateRequest := *openapiclient.NewSubscriptionGroupCreateRequest(*openapiclient.NewSubscriptionGroupCreateRequestData("Type_example", *openapiclient.NewSubscriptionGroupCreateRequestDataAttributes("ReferenceName_example"), *openapiclient.NewAppEventCreateRequestDataRelationships(*openapiclient.NewAppAvailabilityCreateRequestDataRelationshipsApp(*openapiclient.NewAppAvailabilityRelationshipsAppData("Type_example", "Id_example"))))) // SubscriptionGroupCreateRequest | SubscriptionGroup representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.SubscriptionGroupsApi.SubscriptionGroupsCreateInstance(context.Background()).SubscriptionGroupCreateRequest(subscriptionGroupCreateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `SubscriptionGroupsApi.SubscriptionGroupsCreateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `SubscriptionGroupsCreateInstance`: SubscriptionGroupResponse
    fmt.Fprintf(os.Stdout, "Response from `SubscriptionGroupsApi.SubscriptionGroupsCreateInstance`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiSubscriptionGroupsCreateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **subscriptionGroupCreateRequest** | [**SubscriptionGroupCreateRequest**](SubscriptionGroupCreateRequest.md) | SubscriptionGroup representation | 

### Return type

[**SubscriptionGroupResponse**](SubscriptionGroupResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## SubscriptionGroupsDeleteInstance

> SubscriptionGroupsDeleteInstance(ctx, id).Execute()



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
    r, err := apiClient.SubscriptionGroupsApi.SubscriptionGroupsDeleteInstance(context.Background(), id).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `SubscriptionGroupsApi.SubscriptionGroupsDeleteInstance``: %v\n", err)
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

Other parameters are passed through a pointer to a apiSubscriptionGroupsDeleteInstanceRequest struct via the builder pattern


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


## SubscriptionGroupsGetInstance

> SubscriptionGroupResponse SubscriptionGroupsGetInstance(ctx, id).FieldsSubscriptionGroups(fieldsSubscriptionGroups).Include(include).FieldsSubscriptions(fieldsSubscriptions).FieldsSubscriptionGroupLocalizations(fieldsSubscriptionGroupLocalizations).LimitSubscriptionGroupLocalizations(limitSubscriptionGroupLocalizations).LimitSubscriptions(limitSubscriptions).Execute()



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
    fieldsSubscriptionGroups := []string{"FieldsSubscriptionGroups_example"} // []string | the fields to include for returned resources of type subscriptionGroups (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)
    fieldsSubscriptions := []string{"FieldsSubscriptions_example"} // []string | the fields to include for returned resources of type subscriptions (optional)
    fieldsSubscriptionGroupLocalizations := []string{"FieldsSubscriptionGroupLocalizations_example"} // []string | the fields to include for returned resources of type subscriptionGroupLocalizations (optional)
    limitSubscriptionGroupLocalizations := int32(56) // int32 | maximum number of related subscriptionGroupLocalizations returned (when they are included) (optional)
    limitSubscriptions := int32(56) // int32 | maximum number of related subscriptions returned (when they are included) (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.SubscriptionGroupsApi.SubscriptionGroupsGetInstance(context.Background(), id).FieldsSubscriptionGroups(fieldsSubscriptionGroups).Include(include).FieldsSubscriptions(fieldsSubscriptions).FieldsSubscriptionGroupLocalizations(fieldsSubscriptionGroupLocalizations).LimitSubscriptionGroupLocalizations(limitSubscriptionGroupLocalizations).LimitSubscriptions(limitSubscriptions).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `SubscriptionGroupsApi.SubscriptionGroupsGetInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `SubscriptionGroupsGetInstance`: SubscriptionGroupResponse
    fmt.Fprintf(os.Stdout, "Response from `SubscriptionGroupsApi.SubscriptionGroupsGetInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiSubscriptionGroupsGetInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsSubscriptionGroups** | **[]string** | the fields to include for returned resources of type subscriptionGroups | 
 **include** | **[]string** | comma-separated list of relationships to include | 
 **fieldsSubscriptions** | **[]string** | the fields to include for returned resources of type subscriptions | 
 **fieldsSubscriptionGroupLocalizations** | **[]string** | the fields to include for returned resources of type subscriptionGroupLocalizations | 
 **limitSubscriptionGroupLocalizations** | **int32** | maximum number of related subscriptionGroupLocalizations returned (when they are included) | 
 **limitSubscriptions** | **int32** | maximum number of related subscriptions returned (when they are included) | 

### Return type

[**SubscriptionGroupResponse**](SubscriptionGroupResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## SubscriptionGroupsSubscriptionGroupLocalizationsGetToManyRelated

> SubscriptionGroupLocalizationsResponse SubscriptionGroupsSubscriptionGroupLocalizationsGetToManyRelated(ctx, id).FieldsSubscriptionGroups(fieldsSubscriptionGroups).FieldsSubscriptionGroupLocalizations(fieldsSubscriptionGroupLocalizations).Limit(limit).Include(include).Execute()



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
    fieldsSubscriptionGroups := []string{"FieldsSubscriptionGroups_example"} // []string | the fields to include for returned resources of type subscriptionGroups (optional)
    fieldsSubscriptionGroupLocalizations := []string{"FieldsSubscriptionGroupLocalizations_example"} // []string | the fields to include for returned resources of type subscriptionGroupLocalizations (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.SubscriptionGroupsApi.SubscriptionGroupsSubscriptionGroupLocalizationsGetToManyRelated(context.Background(), id).FieldsSubscriptionGroups(fieldsSubscriptionGroups).FieldsSubscriptionGroupLocalizations(fieldsSubscriptionGroupLocalizations).Limit(limit).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `SubscriptionGroupsApi.SubscriptionGroupsSubscriptionGroupLocalizationsGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `SubscriptionGroupsSubscriptionGroupLocalizationsGetToManyRelated`: SubscriptionGroupLocalizationsResponse
    fmt.Fprintf(os.Stdout, "Response from `SubscriptionGroupsApi.SubscriptionGroupsSubscriptionGroupLocalizationsGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiSubscriptionGroupsSubscriptionGroupLocalizationsGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsSubscriptionGroups** | **[]string** | the fields to include for returned resources of type subscriptionGroups | 
 **fieldsSubscriptionGroupLocalizations** | **[]string** | the fields to include for returned resources of type subscriptionGroupLocalizations | 
 **limit** | **int32** | maximum resources per page | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**SubscriptionGroupLocalizationsResponse**](SubscriptionGroupLocalizationsResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## SubscriptionGroupsSubscriptionsGetToManyRelated

> SubscriptionsResponse SubscriptionGroupsSubscriptionsGetToManyRelated(ctx, id).FilterName(filterName).FilterProductId(filterProductId).FilterState(filterState).Sort(sort).FieldsPromotedPurchases(fieldsPromotedPurchases).FieldsSubscriptionPromotionalOffers(fieldsSubscriptionPromotionalOffers).FieldsSubscriptionOfferCodes(fieldsSubscriptionOfferCodes).FieldsSubscriptionAppStoreReviewScreenshots(fieldsSubscriptionAppStoreReviewScreenshots).FieldsSubscriptions(fieldsSubscriptions).FieldsSubscriptionGroups(fieldsSubscriptionGroups).FieldsSubscriptionIntroductoryOffers(fieldsSubscriptionIntroductoryOffers).FieldsSubscriptionPrices(fieldsSubscriptionPrices).FieldsSubscriptionLocalizations(fieldsSubscriptionLocalizations).Limit(limit).LimitSubscriptionLocalizations(limitSubscriptionLocalizations).LimitIntroductoryOffers(limitIntroductoryOffers).LimitPromotionalOffers(limitPromotionalOffers).LimitOfferCodes(limitOfferCodes).LimitPrices(limitPrices).Include(include).Execute()



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
    filterName := []string{"Inner_example"} // []string | filter by attribute 'name' (optional)
    filterProductId := []string{"Inner_example"} // []string | filter by attribute 'productId' (optional)
    filterState := []string{"FilterState_example"} // []string | filter by attribute 'state' (optional)
    sort := []string{"Sort_example"} // []string | comma-separated list of sort expressions; resources will be sorted as specified (optional)
    fieldsPromotedPurchases := []string{"FieldsPromotedPurchases_example"} // []string | the fields to include for returned resources of type promotedPurchases (optional)
    fieldsSubscriptionPromotionalOffers := []string{"FieldsSubscriptionPromotionalOffers_example"} // []string | the fields to include for returned resources of type subscriptionPromotionalOffers (optional)
    fieldsSubscriptionOfferCodes := []string{"FieldsSubscriptionOfferCodes_example"} // []string | the fields to include for returned resources of type subscriptionOfferCodes (optional)
    fieldsSubscriptionAppStoreReviewScreenshots := []string{"FieldsSubscriptionAppStoreReviewScreenshots_example"} // []string | the fields to include for returned resources of type subscriptionAppStoreReviewScreenshots (optional)
    fieldsSubscriptions := []string{"FieldsSubscriptions_example"} // []string | the fields to include for returned resources of type subscriptions (optional)
    fieldsSubscriptionGroups := []string{"FieldsSubscriptionGroups_example"} // []string | the fields to include for returned resources of type subscriptionGroups (optional)
    fieldsSubscriptionIntroductoryOffers := []string{"FieldsSubscriptionIntroductoryOffers_example"} // []string | the fields to include for returned resources of type subscriptionIntroductoryOffers (optional)
    fieldsSubscriptionPrices := []string{"FieldsSubscriptionPrices_example"} // []string | the fields to include for returned resources of type subscriptionPrices (optional)
    fieldsSubscriptionLocalizations := []string{"FieldsSubscriptionLocalizations_example"} // []string | the fields to include for returned resources of type subscriptionLocalizations (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    limitSubscriptionLocalizations := int32(56) // int32 | maximum number of related subscriptionLocalizations returned (when they are included) (optional)
    limitIntroductoryOffers := int32(56) // int32 | maximum number of related introductoryOffers returned (when they are included) (optional)
    limitPromotionalOffers := int32(56) // int32 | maximum number of related promotionalOffers returned (when they are included) (optional)
    limitOfferCodes := int32(56) // int32 | maximum number of related offerCodes returned (when they are included) (optional)
    limitPrices := int32(56) // int32 | maximum number of related prices returned (when they are included) (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.SubscriptionGroupsApi.SubscriptionGroupsSubscriptionsGetToManyRelated(context.Background(), id).FilterName(filterName).FilterProductId(filterProductId).FilterState(filterState).Sort(sort).FieldsPromotedPurchases(fieldsPromotedPurchases).FieldsSubscriptionPromotionalOffers(fieldsSubscriptionPromotionalOffers).FieldsSubscriptionOfferCodes(fieldsSubscriptionOfferCodes).FieldsSubscriptionAppStoreReviewScreenshots(fieldsSubscriptionAppStoreReviewScreenshots).FieldsSubscriptions(fieldsSubscriptions).FieldsSubscriptionGroups(fieldsSubscriptionGroups).FieldsSubscriptionIntroductoryOffers(fieldsSubscriptionIntroductoryOffers).FieldsSubscriptionPrices(fieldsSubscriptionPrices).FieldsSubscriptionLocalizations(fieldsSubscriptionLocalizations).Limit(limit).LimitSubscriptionLocalizations(limitSubscriptionLocalizations).LimitIntroductoryOffers(limitIntroductoryOffers).LimitPromotionalOffers(limitPromotionalOffers).LimitOfferCodes(limitOfferCodes).LimitPrices(limitPrices).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `SubscriptionGroupsApi.SubscriptionGroupsSubscriptionsGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `SubscriptionGroupsSubscriptionsGetToManyRelated`: SubscriptionsResponse
    fmt.Fprintf(os.Stdout, "Response from `SubscriptionGroupsApi.SubscriptionGroupsSubscriptionsGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiSubscriptionGroupsSubscriptionsGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **filterName** | **[]string** | filter by attribute &#39;name&#39; | 
 **filterProductId** | **[]string** | filter by attribute &#39;productId&#39; | 
 **filterState** | **[]string** | filter by attribute &#39;state&#39; | 
 **sort** | **[]string** | comma-separated list of sort expressions; resources will be sorted as specified | 
 **fieldsPromotedPurchases** | **[]string** | the fields to include for returned resources of type promotedPurchases | 
 **fieldsSubscriptionPromotionalOffers** | **[]string** | the fields to include for returned resources of type subscriptionPromotionalOffers | 
 **fieldsSubscriptionOfferCodes** | **[]string** | the fields to include for returned resources of type subscriptionOfferCodes | 
 **fieldsSubscriptionAppStoreReviewScreenshots** | **[]string** | the fields to include for returned resources of type subscriptionAppStoreReviewScreenshots | 
 **fieldsSubscriptions** | **[]string** | the fields to include for returned resources of type subscriptions | 
 **fieldsSubscriptionGroups** | **[]string** | the fields to include for returned resources of type subscriptionGroups | 
 **fieldsSubscriptionIntroductoryOffers** | **[]string** | the fields to include for returned resources of type subscriptionIntroductoryOffers | 
 **fieldsSubscriptionPrices** | **[]string** | the fields to include for returned resources of type subscriptionPrices | 
 **fieldsSubscriptionLocalizations** | **[]string** | the fields to include for returned resources of type subscriptionLocalizations | 
 **limit** | **int32** | maximum resources per page | 
 **limitSubscriptionLocalizations** | **int32** | maximum number of related subscriptionLocalizations returned (when they are included) | 
 **limitIntroductoryOffers** | **int32** | maximum number of related introductoryOffers returned (when they are included) | 
 **limitPromotionalOffers** | **int32** | maximum number of related promotionalOffers returned (when they are included) | 
 **limitOfferCodes** | **int32** | maximum number of related offerCodes returned (when they are included) | 
 **limitPrices** | **int32** | maximum number of related prices returned (when they are included) | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**SubscriptionsResponse**](SubscriptionsResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## SubscriptionGroupsUpdateInstance

> SubscriptionGroupResponse SubscriptionGroupsUpdateInstance(ctx, id).SubscriptionGroupUpdateRequest(subscriptionGroupUpdateRequest).Execute()



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
    subscriptionGroupUpdateRequest := *openapiclient.NewSubscriptionGroupUpdateRequest(*openapiclient.NewSubscriptionGroupUpdateRequestData("Type_example", "Id_example")) // SubscriptionGroupUpdateRequest | SubscriptionGroup representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.SubscriptionGroupsApi.SubscriptionGroupsUpdateInstance(context.Background(), id).SubscriptionGroupUpdateRequest(subscriptionGroupUpdateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `SubscriptionGroupsApi.SubscriptionGroupsUpdateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `SubscriptionGroupsUpdateInstance`: SubscriptionGroupResponse
    fmt.Fprintf(os.Stdout, "Response from `SubscriptionGroupsApi.SubscriptionGroupsUpdateInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiSubscriptionGroupsUpdateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **subscriptionGroupUpdateRequest** | [**SubscriptionGroupUpdateRequest**](SubscriptionGroupUpdateRequest.md) | SubscriptionGroup representation | 

### Return type

[**SubscriptionGroupResponse**](SubscriptionGroupResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

