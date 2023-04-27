# \InAppPurchasesApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**InAppPurchasesAppStoreReviewScreenshotGetToOneRelated**](InAppPurchasesApi.md#InAppPurchasesAppStoreReviewScreenshotGetToOneRelated) | **Get** /v2/inAppPurchases/{id}/appStoreReviewScreenshot | 
[**InAppPurchasesContentGetToOneRelated**](InAppPurchasesApi.md#InAppPurchasesContentGetToOneRelated) | **Get** /v2/inAppPurchases/{id}/content | 
[**InAppPurchasesCreateInstance**](InAppPurchasesApi.md#InAppPurchasesCreateInstance) | **Post** /v2/inAppPurchases | 
[**InAppPurchasesDeleteInstance**](InAppPurchasesApi.md#InAppPurchasesDeleteInstance) | **Delete** /v2/inAppPurchases/{id} | 
[**InAppPurchasesGetInstance**](InAppPurchasesApi.md#InAppPurchasesGetInstance) | **Get** /v1/inAppPurchases/{id} | 
[**InAppPurchasesGetInstance_0**](InAppPurchasesApi.md#InAppPurchasesGetInstance_0) | **Get** /v2/inAppPurchases/{id} | 
[**InAppPurchasesIapPriceScheduleGetToOneRelated**](InAppPurchasesApi.md#InAppPurchasesIapPriceScheduleGetToOneRelated) | **Get** /v2/inAppPurchases/{id}/iapPriceSchedule | 
[**InAppPurchasesInAppPurchaseLocalizationsGetToManyRelated**](InAppPurchasesApi.md#InAppPurchasesInAppPurchaseLocalizationsGetToManyRelated) | **Get** /v2/inAppPurchases/{id}/inAppPurchaseLocalizations | 
[**InAppPurchasesPricePointsGetToManyRelated**](InAppPurchasesApi.md#InAppPurchasesPricePointsGetToManyRelated) | **Get** /v2/inAppPurchases/{id}/pricePoints | 
[**InAppPurchasesPromotedPurchaseGetToOneRelated**](InAppPurchasesApi.md#InAppPurchasesPromotedPurchaseGetToOneRelated) | **Get** /v2/inAppPurchases/{id}/promotedPurchase | 
[**InAppPurchasesUpdateInstance**](InAppPurchasesApi.md#InAppPurchasesUpdateInstance) | **Patch** /v2/inAppPurchases/{id} | 



## InAppPurchasesAppStoreReviewScreenshotGetToOneRelated

> InAppPurchaseAppStoreReviewScreenshotResponse InAppPurchasesAppStoreReviewScreenshotGetToOneRelated(ctx, id).FieldsInAppPurchaseAppStoreReviewScreenshots(fieldsInAppPurchaseAppStoreReviewScreenshots).FieldsInAppPurchases(fieldsInAppPurchases).Include(include).Execute()



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
    fieldsInAppPurchaseAppStoreReviewScreenshots := []string{"FieldsInAppPurchaseAppStoreReviewScreenshots_example"} // []string | the fields to include for returned resources of type inAppPurchaseAppStoreReviewScreenshots (optional)
    fieldsInAppPurchases := []string{"FieldsInAppPurchases_example"} // []string | the fields to include for returned resources of type inAppPurchases (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.InAppPurchasesApi.InAppPurchasesAppStoreReviewScreenshotGetToOneRelated(context.Background(), id).FieldsInAppPurchaseAppStoreReviewScreenshots(fieldsInAppPurchaseAppStoreReviewScreenshots).FieldsInAppPurchases(fieldsInAppPurchases).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `InAppPurchasesApi.InAppPurchasesAppStoreReviewScreenshotGetToOneRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `InAppPurchasesAppStoreReviewScreenshotGetToOneRelated`: InAppPurchaseAppStoreReviewScreenshotResponse
    fmt.Fprintf(os.Stdout, "Response from `InAppPurchasesApi.InAppPurchasesAppStoreReviewScreenshotGetToOneRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiInAppPurchasesAppStoreReviewScreenshotGetToOneRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsInAppPurchaseAppStoreReviewScreenshots** | **[]string** | the fields to include for returned resources of type inAppPurchaseAppStoreReviewScreenshots | 
 **fieldsInAppPurchases** | **[]string** | the fields to include for returned resources of type inAppPurchases | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**InAppPurchaseAppStoreReviewScreenshotResponse**](InAppPurchaseAppStoreReviewScreenshotResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## InAppPurchasesContentGetToOneRelated

> InAppPurchaseContentResponse InAppPurchasesContentGetToOneRelated(ctx, id).FieldsInAppPurchases(fieldsInAppPurchases).FieldsInAppPurchaseContents(fieldsInAppPurchaseContents).Include(include).Execute()



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
    fieldsInAppPurchases := []string{"FieldsInAppPurchases_example"} // []string | the fields to include for returned resources of type inAppPurchases (optional)
    fieldsInAppPurchaseContents := []string{"FieldsInAppPurchaseContents_example"} // []string | the fields to include for returned resources of type inAppPurchaseContents (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.InAppPurchasesApi.InAppPurchasesContentGetToOneRelated(context.Background(), id).FieldsInAppPurchases(fieldsInAppPurchases).FieldsInAppPurchaseContents(fieldsInAppPurchaseContents).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `InAppPurchasesApi.InAppPurchasesContentGetToOneRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `InAppPurchasesContentGetToOneRelated`: InAppPurchaseContentResponse
    fmt.Fprintf(os.Stdout, "Response from `InAppPurchasesApi.InAppPurchasesContentGetToOneRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiInAppPurchasesContentGetToOneRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsInAppPurchases** | **[]string** | the fields to include for returned resources of type inAppPurchases | 
 **fieldsInAppPurchaseContents** | **[]string** | the fields to include for returned resources of type inAppPurchaseContents | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**InAppPurchaseContentResponse**](InAppPurchaseContentResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## InAppPurchasesCreateInstance

> InAppPurchaseV2Response InAppPurchasesCreateInstance(ctx).InAppPurchaseV2CreateRequest(inAppPurchaseV2CreateRequest).Execute()



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
    inAppPurchaseV2CreateRequest := *openapiclient.NewInAppPurchaseV2CreateRequest(*openapiclient.NewInAppPurchaseV2CreateRequestData("Type_example", *openapiclient.NewInAppPurchaseV2CreateRequestDataAttributes("Name_example", "ProductId_example", openapiclient.InAppPurchaseType("CONSUMABLE")), *openapiclient.NewAppEventCreateRequestDataRelationships(*openapiclient.NewAppAvailabilityCreateRequestDataRelationshipsApp(*openapiclient.NewAppAvailabilityRelationshipsAppData("Type_example", "Id_example"))))) // InAppPurchaseV2CreateRequest | InAppPurchase representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.InAppPurchasesApi.InAppPurchasesCreateInstance(context.Background()).InAppPurchaseV2CreateRequest(inAppPurchaseV2CreateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `InAppPurchasesApi.InAppPurchasesCreateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `InAppPurchasesCreateInstance`: InAppPurchaseV2Response
    fmt.Fprintf(os.Stdout, "Response from `InAppPurchasesApi.InAppPurchasesCreateInstance`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiInAppPurchasesCreateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **inAppPurchaseV2CreateRequest** | [**InAppPurchaseV2CreateRequest**](InAppPurchaseV2CreateRequest.md) | InAppPurchase representation | 

### Return type

[**InAppPurchaseV2Response**](InAppPurchaseV2Response.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## InAppPurchasesDeleteInstance

> InAppPurchasesDeleteInstance(ctx, id).Execute()



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
    r, err := apiClient.InAppPurchasesApi.InAppPurchasesDeleteInstance(context.Background(), id).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `InAppPurchasesApi.InAppPurchasesDeleteInstance``: %v\n", err)
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

Other parameters are passed through a pointer to a apiInAppPurchasesDeleteInstanceRequest struct via the builder pattern


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


## InAppPurchasesGetInstance

> InAppPurchaseResponse InAppPurchasesGetInstance(ctx, id).FieldsInAppPurchases(fieldsInAppPurchases).Include(include).LimitApps(limitApps).Execute()



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
    fieldsInAppPurchases := []string{"FieldsInAppPurchases_example"} // []string | the fields to include for returned resources of type inAppPurchases (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)
    limitApps := int32(56) // int32 | maximum number of related apps returned (when they are included) (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.InAppPurchasesApi.InAppPurchasesGetInstance(context.Background(), id).FieldsInAppPurchases(fieldsInAppPurchases).Include(include).LimitApps(limitApps).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `InAppPurchasesApi.InAppPurchasesGetInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `InAppPurchasesGetInstance`: InAppPurchaseResponse
    fmt.Fprintf(os.Stdout, "Response from `InAppPurchasesApi.InAppPurchasesGetInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiInAppPurchasesGetInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsInAppPurchases** | **[]string** | the fields to include for returned resources of type inAppPurchases | 
 **include** | **[]string** | comma-separated list of relationships to include | 
 **limitApps** | **int32** | maximum number of related apps returned (when they are included) | 

### Return type

[**InAppPurchaseResponse**](InAppPurchaseResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## InAppPurchasesGetInstance_0

> InAppPurchaseV2Response InAppPurchasesGetInstance_0(ctx, id).FieldsInAppPurchases(fieldsInAppPurchases).Include(include).FieldsInAppPurchaseAppStoreReviewScreenshots(fieldsInAppPurchaseAppStoreReviewScreenshots).FieldsPromotedPurchases(fieldsPromotedPurchases).FieldsInAppPurchasePricePoints(fieldsInAppPurchasePricePoints).FieldsInAppPurchaseLocalizations(fieldsInAppPurchaseLocalizations).FieldsInAppPurchasePriceSchedules(fieldsInAppPurchasePriceSchedules).FieldsInAppPurchaseContents(fieldsInAppPurchaseContents).LimitInAppPurchaseLocalizations(limitInAppPurchaseLocalizations).LimitPricePoints(limitPricePoints).Execute()



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
    fieldsInAppPurchases := []string{"FieldsInAppPurchases_example"} // []string | the fields to include for returned resources of type inAppPurchases (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)
    fieldsInAppPurchaseAppStoreReviewScreenshots := []string{"FieldsInAppPurchaseAppStoreReviewScreenshots_example"} // []string | the fields to include for returned resources of type inAppPurchaseAppStoreReviewScreenshots (optional)
    fieldsPromotedPurchases := []string{"FieldsPromotedPurchases_example"} // []string | the fields to include for returned resources of type promotedPurchases (optional)
    fieldsInAppPurchasePricePoints := []string{"FieldsInAppPurchasePricePoints_example"} // []string | the fields to include for returned resources of type inAppPurchasePricePoints (optional)
    fieldsInAppPurchaseLocalizations := []string{"FieldsInAppPurchaseLocalizations_example"} // []string | the fields to include for returned resources of type inAppPurchaseLocalizations (optional)
    fieldsInAppPurchasePriceSchedules := []string{"FieldsInAppPurchasePriceSchedules_example"} // []string | the fields to include for returned resources of type inAppPurchasePriceSchedules (optional)
    fieldsInAppPurchaseContents := []string{"FieldsInAppPurchaseContents_example"} // []string | the fields to include for returned resources of type inAppPurchaseContents (optional)
    limitInAppPurchaseLocalizations := int32(56) // int32 | maximum number of related inAppPurchaseLocalizations returned (when they are included) (optional)
    limitPricePoints := int32(56) // int32 | maximum number of related pricePoints returned (when they are included) (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.InAppPurchasesApi.InAppPurchasesGetInstance_0(context.Background(), id).FieldsInAppPurchases(fieldsInAppPurchases).Include(include).FieldsInAppPurchaseAppStoreReviewScreenshots(fieldsInAppPurchaseAppStoreReviewScreenshots).FieldsPromotedPurchases(fieldsPromotedPurchases).FieldsInAppPurchasePricePoints(fieldsInAppPurchasePricePoints).FieldsInAppPurchaseLocalizations(fieldsInAppPurchaseLocalizations).FieldsInAppPurchasePriceSchedules(fieldsInAppPurchasePriceSchedules).FieldsInAppPurchaseContents(fieldsInAppPurchaseContents).LimitInAppPurchaseLocalizations(limitInAppPurchaseLocalizations).LimitPricePoints(limitPricePoints).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `InAppPurchasesApi.InAppPurchasesGetInstance_0``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `InAppPurchasesGetInstance_0`: InAppPurchaseV2Response
    fmt.Fprintf(os.Stdout, "Response from `InAppPurchasesApi.InAppPurchasesGetInstance_0`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiInAppPurchasesGetInstance_1Request struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsInAppPurchases** | **[]string** | the fields to include for returned resources of type inAppPurchases | 
 **include** | **[]string** | comma-separated list of relationships to include | 
 **fieldsInAppPurchaseAppStoreReviewScreenshots** | **[]string** | the fields to include for returned resources of type inAppPurchaseAppStoreReviewScreenshots | 
 **fieldsPromotedPurchases** | **[]string** | the fields to include for returned resources of type promotedPurchases | 
 **fieldsInAppPurchasePricePoints** | **[]string** | the fields to include for returned resources of type inAppPurchasePricePoints | 
 **fieldsInAppPurchaseLocalizations** | **[]string** | the fields to include for returned resources of type inAppPurchaseLocalizations | 
 **fieldsInAppPurchasePriceSchedules** | **[]string** | the fields to include for returned resources of type inAppPurchasePriceSchedules | 
 **fieldsInAppPurchaseContents** | **[]string** | the fields to include for returned resources of type inAppPurchaseContents | 
 **limitInAppPurchaseLocalizations** | **int32** | maximum number of related inAppPurchaseLocalizations returned (when they are included) | 
 **limitPricePoints** | **int32** | maximum number of related pricePoints returned (when they are included) | 

### Return type

[**InAppPurchaseV2Response**](InAppPurchaseV2Response.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## InAppPurchasesIapPriceScheduleGetToOneRelated

> InAppPurchasePriceScheduleResponse InAppPurchasesIapPriceScheduleGetToOneRelated(ctx, id).FieldsInAppPurchasePrices(fieldsInAppPurchasePrices).FieldsInAppPurchases(fieldsInAppPurchases).FieldsInAppPurchasePriceSchedules(fieldsInAppPurchasePriceSchedules).FieldsTerritories(fieldsTerritories).LimitManualPrices(limitManualPrices).LimitAutomaticPrices(limitAutomaticPrices).Include(include).Execute()



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
    fieldsInAppPurchasePrices := []string{"FieldsInAppPurchasePrices_example"} // []string | the fields to include for returned resources of type inAppPurchasePrices (optional)
    fieldsInAppPurchases := []string{"FieldsInAppPurchases_example"} // []string | the fields to include for returned resources of type inAppPurchases (optional)
    fieldsInAppPurchasePriceSchedules := []string{"FieldsInAppPurchasePriceSchedules_example"} // []string | the fields to include for returned resources of type inAppPurchasePriceSchedules (optional)
    fieldsTerritories := []string{"FieldsTerritories_example"} // []string | the fields to include for returned resources of type territories (optional)
    limitManualPrices := int32(56) // int32 | maximum number of related manualPrices returned (when they are included) (optional)
    limitAutomaticPrices := int32(56) // int32 | maximum number of related automaticPrices returned (when they are included) (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.InAppPurchasesApi.InAppPurchasesIapPriceScheduleGetToOneRelated(context.Background(), id).FieldsInAppPurchasePrices(fieldsInAppPurchasePrices).FieldsInAppPurchases(fieldsInAppPurchases).FieldsInAppPurchasePriceSchedules(fieldsInAppPurchasePriceSchedules).FieldsTerritories(fieldsTerritories).LimitManualPrices(limitManualPrices).LimitAutomaticPrices(limitAutomaticPrices).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `InAppPurchasesApi.InAppPurchasesIapPriceScheduleGetToOneRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `InAppPurchasesIapPriceScheduleGetToOneRelated`: InAppPurchasePriceScheduleResponse
    fmt.Fprintf(os.Stdout, "Response from `InAppPurchasesApi.InAppPurchasesIapPriceScheduleGetToOneRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiInAppPurchasesIapPriceScheduleGetToOneRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsInAppPurchasePrices** | **[]string** | the fields to include for returned resources of type inAppPurchasePrices | 
 **fieldsInAppPurchases** | **[]string** | the fields to include for returned resources of type inAppPurchases | 
 **fieldsInAppPurchasePriceSchedules** | **[]string** | the fields to include for returned resources of type inAppPurchasePriceSchedules | 
 **fieldsTerritories** | **[]string** | the fields to include for returned resources of type territories | 
 **limitManualPrices** | **int32** | maximum number of related manualPrices returned (when they are included) | 
 **limitAutomaticPrices** | **int32** | maximum number of related automaticPrices returned (when they are included) | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**InAppPurchasePriceScheduleResponse**](InAppPurchasePriceScheduleResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## InAppPurchasesInAppPurchaseLocalizationsGetToManyRelated

> InAppPurchaseLocalizationsResponse InAppPurchasesInAppPurchaseLocalizationsGetToManyRelated(ctx, id).FieldsInAppPurchaseLocalizations(fieldsInAppPurchaseLocalizations).FieldsInAppPurchases(fieldsInAppPurchases).Limit(limit).Include(include).Execute()



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
    fieldsInAppPurchases := []string{"FieldsInAppPurchases_example"} // []string | the fields to include for returned resources of type inAppPurchases (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.InAppPurchasesApi.InAppPurchasesInAppPurchaseLocalizationsGetToManyRelated(context.Background(), id).FieldsInAppPurchaseLocalizations(fieldsInAppPurchaseLocalizations).FieldsInAppPurchases(fieldsInAppPurchases).Limit(limit).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `InAppPurchasesApi.InAppPurchasesInAppPurchaseLocalizationsGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `InAppPurchasesInAppPurchaseLocalizationsGetToManyRelated`: InAppPurchaseLocalizationsResponse
    fmt.Fprintf(os.Stdout, "Response from `InAppPurchasesApi.InAppPurchasesInAppPurchaseLocalizationsGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiInAppPurchasesInAppPurchaseLocalizationsGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsInAppPurchaseLocalizations** | **[]string** | the fields to include for returned resources of type inAppPurchaseLocalizations | 
 **fieldsInAppPurchases** | **[]string** | the fields to include for returned resources of type inAppPurchases | 
 **limit** | **int32** | maximum resources per page | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**InAppPurchaseLocalizationsResponse**](InAppPurchaseLocalizationsResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## InAppPurchasesPricePointsGetToManyRelated

> InAppPurchasePricePointsResponse InAppPurchasesPricePointsGetToManyRelated(ctx, id).FilterPriceTier(filterPriceTier).FilterTerritory(filterTerritory).FieldsInAppPurchasePricePoints(fieldsInAppPurchasePricePoints).FieldsTerritories(fieldsTerritories).Limit(limit).Include(include).Execute()



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
    filterPriceTier := []string{"Inner_example"} // []string | filter by attribute 'priceTier' (optional)
    filterTerritory := []string{"Inner_example"} // []string | filter by id(s) of related 'territory' (optional)
    fieldsInAppPurchasePricePoints := []string{"FieldsInAppPurchasePricePoints_example"} // []string | the fields to include for returned resources of type inAppPurchasePricePoints (optional)
    fieldsTerritories := []string{"FieldsTerritories_example"} // []string | the fields to include for returned resources of type territories (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.InAppPurchasesApi.InAppPurchasesPricePointsGetToManyRelated(context.Background(), id).FilterPriceTier(filterPriceTier).FilterTerritory(filterTerritory).FieldsInAppPurchasePricePoints(fieldsInAppPurchasePricePoints).FieldsTerritories(fieldsTerritories).Limit(limit).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `InAppPurchasesApi.InAppPurchasesPricePointsGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `InAppPurchasesPricePointsGetToManyRelated`: InAppPurchasePricePointsResponse
    fmt.Fprintf(os.Stdout, "Response from `InAppPurchasesApi.InAppPurchasesPricePointsGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiInAppPurchasesPricePointsGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **filterPriceTier** | **[]string** | filter by attribute &#39;priceTier&#39; | 
 **filterTerritory** | **[]string** | filter by id(s) of related &#39;territory&#39; | 
 **fieldsInAppPurchasePricePoints** | **[]string** | the fields to include for returned resources of type inAppPurchasePricePoints | 
 **fieldsTerritories** | **[]string** | the fields to include for returned resources of type territories | 
 **limit** | **int32** | maximum resources per page | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**InAppPurchasePricePointsResponse**](InAppPurchasePricePointsResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json, text/csv

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## InAppPurchasesPromotedPurchaseGetToOneRelated

> PromotedPurchaseResponse InAppPurchasesPromotedPurchaseGetToOneRelated(ctx, id).FieldsPromotedPurchases(fieldsPromotedPurchases).FieldsSubscriptions(fieldsSubscriptions).FieldsInAppPurchases(fieldsInAppPurchases).FieldsPromotedPurchaseImages(fieldsPromotedPurchaseImages).LimitPromotionImages(limitPromotionImages).Include(include).Execute()



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
    resp, r, err := apiClient.InAppPurchasesApi.InAppPurchasesPromotedPurchaseGetToOneRelated(context.Background(), id).FieldsPromotedPurchases(fieldsPromotedPurchases).FieldsSubscriptions(fieldsSubscriptions).FieldsInAppPurchases(fieldsInAppPurchases).FieldsPromotedPurchaseImages(fieldsPromotedPurchaseImages).LimitPromotionImages(limitPromotionImages).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `InAppPurchasesApi.InAppPurchasesPromotedPurchaseGetToOneRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `InAppPurchasesPromotedPurchaseGetToOneRelated`: PromotedPurchaseResponse
    fmt.Fprintf(os.Stdout, "Response from `InAppPurchasesApi.InAppPurchasesPromotedPurchaseGetToOneRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiInAppPurchasesPromotedPurchaseGetToOneRelatedRequest struct via the builder pattern


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


## InAppPurchasesUpdateInstance

> InAppPurchaseV2Response InAppPurchasesUpdateInstance(ctx, id).InAppPurchaseV2UpdateRequest(inAppPurchaseV2UpdateRequest).Execute()



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
    inAppPurchaseV2UpdateRequest := *openapiclient.NewInAppPurchaseV2UpdateRequest(*openapiclient.NewInAppPurchaseV2UpdateRequestData("Type_example", "Id_example")) // InAppPurchaseV2UpdateRequest | InAppPurchase representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.InAppPurchasesApi.InAppPurchasesUpdateInstance(context.Background(), id).InAppPurchaseV2UpdateRequest(inAppPurchaseV2UpdateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `InAppPurchasesApi.InAppPurchasesUpdateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `InAppPurchasesUpdateInstance`: InAppPurchaseV2Response
    fmt.Fprintf(os.Stdout, "Response from `InAppPurchasesApi.InAppPurchasesUpdateInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiInAppPurchasesUpdateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **inAppPurchaseV2UpdateRequest** | [**InAppPurchaseV2UpdateRequest**](InAppPurchaseV2UpdateRequest.md) | InAppPurchase representation | 

### Return type

[**InAppPurchaseV2Response**](InAppPurchaseV2Response.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

