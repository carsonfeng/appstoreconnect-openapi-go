# \AppPricePointsApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**AppPricePointsEqualizationsGetToManyRelated**](AppPricePointsApi.md#AppPricePointsEqualizationsGetToManyRelated) | **Get** /v3/appPricePoints/{id}/equalizations | 
[**AppPricePointsGetCollection**](AppPricePointsApi.md#AppPricePointsGetCollection) | **Get** /v1/appPricePoints | 
[**AppPricePointsGetInstance**](AppPricePointsApi.md#AppPricePointsGetInstance) | **Get** /v3/appPricePoints/{id} | 
[**AppPricePointsGetInstance_0**](AppPricePointsApi.md#AppPricePointsGetInstance_0) | **Get** /v1/appPricePoints/{id} | 
[**AppPricePointsTerritoryGetToOneRelated**](AppPricePointsApi.md#AppPricePointsTerritoryGetToOneRelated) | **Get** /v1/appPricePoints/{id}/territory | 



## AppPricePointsEqualizationsGetToManyRelated

> AppPricePointsV3Response AppPricePointsEqualizationsGetToManyRelated(ctx, id).FilterTerritory(filterTerritory).FieldsAppPricePoints(fieldsAppPricePoints).FieldsApps(fieldsApps).FieldsTerritories(fieldsTerritories).Limit(limit).Include(include).Execute()



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
    fieldsAppPricePoints := []string{"FieldsAppPricePoints_example"} // []string | the fields to include for returned resources of type appPricePoints (optional)
    fieldsApps := []string{"FieldsApps_example"} // []string | the fields to include for returned resources of type apps (optional)
    fieldsTerritories := []string{"FieldsTerritories_example"} // []string | the fields to include for returned resources of type territories (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppPricePointsApi.AppPricePointsEqualizationsGetToManyRelated(context.Background(), id).FilterTerritory(filterTerritory).FieldsAppPricePoints(fieldsAppPricePoints).FieldsApps(fieldsApps).FieldsTerritories(fieldsTerritories).Limit(limit).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppPricePointsApi.AppPricePointsEqualizationsGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppPricePointsEqualizationsGetToManyRelated`: AppPricePointsV3Response
    fmt.Fprintf(os.Stdout, "Response from `AppPricePointsApi.AppPricePointsEqualizationsGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppPricePointsEqualizationsGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **filterTerritory** | **[]string** | filter by id(s) of related &#39;territory&#39; | 
 **fieldsAppPricePoints** | **[]string** | the fields to include for returned resources of type appPricePoints | 
 **fieldsApps** | **[]string** | the fields to include for returned resources of type apps | 
 **fieldsTerritories** | **[]string** | the fields to include for returned resources of type territories | 
 **limit** | **int32** | maximum resources per page | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**AppPricePointsV3Response**](AppPricePointsV3Response.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json, text/csv

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppPricePointsGetCollection

> AppPricePointsResponse AppPricePointsGetCollection(ctx).FilterPriceTier(filterPriceTier).FilterTerritory(filterTerritory).FieldsAppPricePoints(fieldsAppPricePoints).Limit(limit).Include(include).FieldsTerritories(fieldsTerritories).Execute()



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
    filterPriceTier := []string{"Inner_example"} // []string | filter by id(s) of related 'priceTier' (optional)
    filterTerritory := []string{"Inner_example"} // []string | filter by id(s) of related 'territory' (optional)
    fieldsAppPricePoints := []string{"FieldsAppPricePoints_example"} // []string | the fields to include for returned resources of type appPricePoints (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)
    fieldsTerritories := []string{"FieldsTerritories_example"} // []string | the fields to include for returned resources of type territories (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppPricePointsApi.AppPricePointsGetCollection(context.Background()).FilterPriceTier(filterPriceTier).FilterTerritory(filterTerritory).FieldsAppPricePoints(fieldsAppPricePoints).Limit(limit).Include(include).FieldsTerritories(fieldsTerritories).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppPricePointsApi.AppPricePointsGetCollection``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppPricePointsGetCollection`: AppPricePointsResponse
    fmt.Fprintf(os.Stdout, "Response from `AppPricePointsApi.AppPricePointsGetCollection`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiAppPricePointsGetCollectionRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **filterPriceTier** | **[]string** | filter by id(s) of related &#39;priceTier&#39; | 
 **filterTerritory** | **[]string** | filter by id(s) of related &#39;territory&#39; | 
 **fieldsAppPricePoints** | **[]string** | the fields to include for returned resources of type appPricePoints | 
 **limit** | **int32** | maximum resources per page | 
 **include** | **[]string** | comma-separated list of relationships to include | 
 **fieldsTerritories** | **[]string** | the fields to include for returned resources of type territories | 

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


## AppPricePointsGetInstance

> AppPricePointV3Response AppPricePointsGetInstance(ctx, id).FieldsAppPricePoints(fieldsAppPricePoints).Include(include).Execute()



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
    fieldsAppPricePoints := []string{"FieldsAppPricePoints_example"} // []string | the fields to include for returned resources of type appPricePoints (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppPricePointsApi.AppPricePointsGetInstance(context.Background(), id).FieldsAppPricePoints(fieldsAppPricePoints).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppPricePointsApi.AppPricePointsGetInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppPricePointsGetInstance`: AppPricePointV3Response
    fmt.Fprintf(os.Stdout, "Response from `AppPricePointsApi.AppPricePointsGetInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppPricePointsGetInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsAppPricePoints** | **[]string** | the fields to include for returned resources of type appPricePoints | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**AppPricePointV3Response**](AppPricePointV3Response.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppPricePointsGetInstance_0

> AppPricePointResponse AppPricePointsGetInstance_0(ctx, id).FieldsAppPricePoints(fieldsAppPricePoints).Include(include).FieldsTerritories(fieldsTerritories).Execute()



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
    fieldsAppPricePoints := []string{"FieldsAppPricePoints_example"} // []string | the fields to include for returned resources of type appPricePoints (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)
    fieldsTerritories := []string{"FieldsTerritories_example"} // []string | the fields to include for returned resources of type territories (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppPricePointsApi.AppPricePointsGetInstance_0(context.Background(), id).FieldsAppPricePoints(fieldsAppPricePoints).Include(include).FieldsTerritories(fieldsTerritories).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppPricePointsApi.AppPricePointsGetInstance_0``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppPricePointsGetInstance_0`: AppPricePointResponse
    fmt.Fprintf(os.Stdout, "Response from `AppPricePointsApi.AppPricePointsGetInstance_0`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppPricePointsGetInstance_1Request struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsAppPricePoints** | **[]string** | the fields to include for returned resources of type appPricePoints | 
 **include** | **[]string** | comma-separated list of relationships to include | 
 **fieldsTerritories** | **[]string** | the fields to include for returned resources of type territories | 

### Return type

[**AppPricePointResponse**](AppPricePointResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppPricePointsTerritoryGetToOneRelated

> TerritoryResponse AppPricePointsTerritoryGetToOneRelated(ctx, id).FieldsTerritories(fieldsTerritories).Execute()



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
    fieldsTerritories := []string{"FieldsTerritories_example"} // []string | the fields to include for returned resources of type territories (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppPricePointsApi.AppPricePointsTerritoryGetToOneRelated(context.Background(), id).FieldsTerritories(fieldsTerritories).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppPricePointsApi.AppPricePointsTerritoryGetToOneRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppPricePointsTerritoryGetToOneRelated`: TerritoryResponse
    fmt.Fprintf(os.Stdout, "Response from `AppPricePointsApi.AppPricePointsTerritoryGetToOneRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppPricePointsTerritoryGetToOneRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsTerritories** | **[]string** | the fields to include for returned resources of type territories | 

### Return type

[**TerritoryResponse**](TerritoryResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

