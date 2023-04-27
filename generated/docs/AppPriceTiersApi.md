# \AppPriceTiersApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**AppPriceTiersGetCollection**](AppPriceTiersApi.md#AppPriceTiersGetCollection) | **Get** /v1/appPriceTiers | 
[**AppPriceTiersGetInstance**](AppPriceTiersApi.md#AppPriceTiersGetInstance) | **Get** /v1/appPriceTiers/{id} | 
[**AppPriceTiersPricePointsGetToManyRelated**](AppPriceTiersApi.md#AppPriceTiersPricePointsGetToManyRelated) | **Get** /v1/appPriceTiers/{id}/pricePoints | 



## AppPriceTiersGetCollection

> AppPriceTiersResponse AppPriceTiersGetCollection(ctx).FilterId(filterId).FieldsAppPriceTiers(fieldsAppPriceTiers).Limit(limit).Include(include).FieldsAppPricePoints(fieldsAppPricePoints).LimitPricePoints(limitPricePoints).Execute()



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
    filterId := []string{"Inner_example"} // []string | filter by id(s) (optional)
    fieldsAppPriceTiers := []string{"FieldsAppPriceTiers_example"} // []string | the fields to include for returned resources of type appPriceTiers (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)
    fieldsAppPricePoints := []string{"FieldsAppPricePoints_example"} // []string | the fields to include for returned resources of type appPricePoints (optional)
    limitPricePoints := int32(56) // int32 | maximum number of related pricePoints returned (when they are included) (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppPriceTiersApi.AppPriceTiersGetCollection(context.Background()).FilterId(filterId).FieldsAppPriceTiers(fieldsAppPriceTiers).Limit(limit).Include(include).FieldsAppPricePoints(fieldsAppPricePoints).LimitPricePoints(limitPricePoints).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppPriceTiersApi.AppPriceTiersGetCollection``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppPriceTiersGetCollection`: AppPriceTiersResponse
    fmt.Fprintf(os.Stdout, "Response from `AppPriceTiersApi.AppPriceTiersGetCollection`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiAppPriceTiersGetCollectionRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **filterId** | **[]string** | filter by id(s) | 
 **fieldsAppPriceTiers** | **[]string** | the fields to include for returned resources of type appPriceTiers | 
 **limit** | **int32** | maximum resources per page | 
 **include** | **[]string** | comma-separated list of relationships to include | 
 **fieldsAppPricePoints** | **[]string** | the fields to include for returned resources of type appPricePoints | 
 **limitPricePoints** | **int32** | maximum number of related pricePoints returned (when they are included) | 

### Return type

[**AppPriceTiersResponse**](AppPriceTiersResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppPriceTiersGetInstance

> AppPriceTierResponse AppPriceTiersGetInstance(ctx, id).FieldsAppPriceTiers(fieldsAppPriceTiers).Include(include).FieldsAppPricePoints(fieldsAppPricePoints).LimitPricePoints(limitPricePoints).Execute()



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
    fieldsAppPriceTiers := []string{"FieldsAppPriceTiers_example"} // []string | the fields to include for returned resources of type appPriceTiers (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)
    fieldsAppPricePoints := []string{"FieldsAppPricePoints_example"} // []string | the fields to include for returned resources of type appPricePoints (optional)
    limitPricePoints := int32(56) // int32 | maximum number of related pricePoints returned (when they are included) (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppPriceTiersApi.AppPriceTiersGetInstance(context.Background(), id).FieldsAppPriceTiers(fieldsAppPriceTiers).Include(include).FieldsAppPricePoints(fieldsAppPricePoints).LimitPricePoints(limitPricePoints).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppPriceTiersApi.AppPriceTiersGetInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppPriceTiersGetInstance`: AppPriceTierResponse
    fmt.Fprintf(os.Stdout, "Response from `AppPriceTiersApi.AppPriceTiersGetInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppPriceTiersGetInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsAppPriceTiers** | **[]string** | the fields to include for returned resources of type appPriceTiers | 
 **include** | **[]string** | comma-separated list of relationships to include | 
 **fieldsAppPricePoints** | **[]string** | the fields to include for returned resources of type appPricePoints | 
 **limitPricePoints** | **int32** | maximum number of related pricePoints returned (when they are included) | 

### Return type

[**AppPriceTierResponse**](AppPriceTierResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppPriceTiersPricePointsGetToManyRelated

> AppPricePointsResponse AppPriceTiersPricePointsGetToManyRelated(ctx, id).FilterTerritory(filterTerritory).FieldsAppPriceTiers(fieldsAppPriceTiers).FieldsAppPricePoints(fieldsAppPricePoints).FieldsTerritories(fieldsTerritories).Limit(limit).Include(include).Execute()



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
    fieldsAppPriceTiers := []string{"FieldsAppPriceTiers_example"} // []string | the fields to include for returned resources of type appPriceTiers (optional)
    fieldsAppPricePoints := []string{"FieldsAppPricePoints_example"} // []string | the fields to include for returned resources of type appPricePoints (optional)
    fieldsTerritories := []string{"FieldsTerritories_example"} // []string | the fields to include for returned resources of type territories (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppPriceTiersApi.AppPriceTiersPricePointsGetToManyRelated(context.Background(), id).FilterTerritory(filterTerritory).FieldsAppPriceTiers(fieldsAppPriceTiers).FieldsAppPricePoints(fieldsAppPricePoints).FieldsTerritories(fieldsTerritories).Limit(limit).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppPriceTiersApi.AppPriceTiersPricePointsGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppPriceTiersPricePointsGetToManyRelated`: AppPricePointsResponse
    fmt.Fprintf(os.Stdout, "Response from `AppPriceTiersApi.AppPriceTiersPricePointsGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppPriceTiersPricePointsGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **filterTerritory** | **[]string** | filter by id(s) of related &#39;territory&#39; | 
 **fieldsAppPriceTiers** | **[]string** | the fields to include for returned resources of type appPriceTiers | 
 **fieldsAppPricePoints** | **[]string** | the fields to include for returned resources of type appPricePoints | 
 **fieldsTerritories** | **[]string** | the fields to include for returned resources of type territories | 
 **limit** | **int32** | maximum resources per page | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**AppPricePointsResponse**](AppPricePointsResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

