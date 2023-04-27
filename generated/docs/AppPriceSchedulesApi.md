# \AppPriceSchedulesApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**AppPriceSchedulesAutomaticPricesGetToManyRelated**](AppPriceSchedulesApi.md#AppPriceSchedulesAutomaticPricesGetToManyRelated) | **Get** /v1/appPriceSchedules/{id}/automaticPrices | 
[**AppPriceSchedulesBaseTerritoryGetToOneRelated**](AppPriceSchedulesApi.md#AppPriceSchedulesBaseTerritoryGetToOneRelated) | **Get** /v1/appPriceSchedules/{id}/baseTerritory | 
[**AppPriceSchedulesCreateInstance**](AppPriceSchedulesApi.md#AppPriceSchedulesCreateInstance) | **Post** /v1/appPriceSchedules | 
[**AppPriceSchedulesGetInstance**](AppPriceSchedulesApi.md#AppPriceSchedulesGetInstance) | **Get** /v1/appPriceSchedules/{id} | 
[**AppPriceSchedulesManualPricesGetToManyRelated**](AppPriceSchedulesApi.md#AppPriceSchedulesManualPricesGetToManyRelated) | **Get** /v1/appPriceSchedules/{id}/manualPrices | 



## AppPriceSchedulesAutomaticPricesGetToManyRelated

> AppPricesV2Response AppPriceSchedulesAutomaticPricesGetToManyRelated(ctx, id).FilterEndDate(filterEndDate).FilterStartDate(filterStartDate).FilterTerritory(filterTerritory).FieldsAppPrices(fieldsAppPrices).FieldsAppPricePoints(fieldsAppPricePoints).FieldsTerritories(fieldsTerritories).Limit(limit).Include(include).Execute()



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
    filterEndDate := []string{"Inner_example"} // []string | filter by attribute 'endDate' (optional)
    filterStartDate := []string{"Inner_example"} // []string | filter by attribute 'startDate' (optional)
    filterTerritory := []string{"Inner_example"} // []string | filter by id(s) of related 'territory' (optional)
    fieldsAppPrices := []string{"FieldsAppPrices_example"} // []string | the fields to include for returned resources of type appPrices (optional)
    fieldsAppPricePoints := []string{"FieldsAppPricePoints_example"} // []string | the fields to include for returned resources of type appPricePoints (optional)
    fieldsTerritories := []string{"FieldsTerritories_example"} // []string | the fields to include for returned resources of type territories (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppPriceSchedulesApi.AppPriceSchedulesAutomaticPricesGetToManyRelated(context.Background(), id).FilterEndDate(filterEndDate).FilterStartDate(filterStartDate).FilterTerritory(filterTerritory).FieldsAppPrices(fieldsAppPrices).FieldsAppPricePoints(fieldsAppPricePoints).FieldsTerritories(fieldsTerritories).Limit(limit).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppPriceSchedulesApi.AppPriceSchedulesAutomaticPricesGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppPriceSchedulesAutomaticPricesGetToManyRelated`: AppPricesV2Response
    fmt.Fprintf(os.Stdout, "Response from `AppPriceSchedulesApi.AppPriceSchedulesAutomaticPricesGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppPriceSchedulesAutomaticPricesGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **filterEndDate** | **[]string** | filter by attribute &#39;endDate&#39; | 
 **filterStartDate** | **[]string** | filter by attribute &#39;startDate&#39; | 
 **filterTerritory** | **[]string** | filter by id(s) of related &#39;territory&#39; | 
 **fieldsAppPrices** | **[]string** | the fields to include for returned resources of type appPrices | 
 **fieldsAppPricePoints** | **[]string** | the fields to include for returned resources of type appPricePoints | 
 **fieldsTerritories** | **[]string** | the fields to include for returned resources of type territories | 
 **limit** | **int32** | maximum resources per page | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**AppPricesV2Response**](AppPricesV2Response.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppPriceSchedulesBaseTerritoryGetToOneRelated

> TerritoryResponse AppPriceSchedulesBaseTerritoryGetToOneRelated(ctx, id).FieldsTerritories(fieldsTerritories).Execute()



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
    resp, r, err := apiClient.AppPriceSchedulesApi.AppPriceSchedulesBaseTerritoryGetToOneRelated(context.Background(), id).FieldsTerritories(fieldsTerritories).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppPriceSchedulesApi.AppPriceSchedulesBaseTerritoryGetToOneRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppPriceSchedulesBaseTerritoryGetToOneRelated`: TerritoryResponse
    fmt.Fprintf(os.Stdout, "Response from `AppPriceSchedulesApi.AppPriceSchedulesBaseTerritoryGetToOneRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppPriceSchedulesBaseTerritoryGetToOneRelatedRequest struct via the builder pattern


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


## AppPriceSchedulesCreateInstance

> AppPriceScheduleResponse AppPriceSchedulesCreateInstance(ctx).AppPriceScheduleCreateRequest(appPriceScheduleCreateRequest).Execute()



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
    appPriceScheduleCreateRequest := *openapiclient.NewAppPriceScheduleCreateRequest(*openapiclient.NewAppPriceScheduleCreateRequestData("Type_example", *openapiclient.NewAppPriceScheduleCreateRequestDataRelationships(*openapiclient.NewAppAvailabilityCreateRequestDataRelationshipsApp(*openapiclient.NewAppAvailabilityRelationshipsAppData("Type_example", "Id_example")), *openapiclient.NewAppPriceScheduleCreateRequestDataRelationshipsBaseTerritory(*openapiclient.NewAppAvailabilityRelationshipsAvailableTerritoriesDataInner("Type_example", "Id_example")), *openapiclient.NewAppPriceScheduleCreateRequestDataRelationshipsManualPrices([]openapiclient.AppPriceScheduleRelationshipsManualPricesDataInner{*openapiclient.NewAppPriceScheduleRelationshipsManualPricesDataInner("Type_example", "Id_example")})))) // AppPriceScheduleCreateRequest | AppPriceSchedule representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppPriceSchedulesApi.AppPriceSchedulesCreateInstance(context.Background()).AppPriceScheduleCreateRequest(appPriceScheduleCreateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppPriceSchedulesApi.AppPriceSchedulesCreateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppPriceSchedulesCreateInstance`: AppPriceScheduleResponse
    fmt.Fprintf(os.Stdout, "Response from `AppPriceSchedulesApi.AppPriceSchedulesCreateInstance`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiAppPriceSchedulesCreateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **appPriceScheduleCreateRequest** | [**AppPriceScheduleCreateRequest**](AppPriceScheduleCreateRequest.md) | AppPriceSchedule representation | 

### Return type

[**AppPriceScheduleResponse**](AppPriceScheduleResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppPriceSchedulesGetInstance

> AppPriceScheduleResponse AppPriceSchedulesGetInstance(ctx, id).FieldsAppPriceSchedules(fieldsAppPriceSchedules).Include(include).FieldsAppPrices(fieldsAppPrices).FieldsTerritories(fieldsTerritories).LimitAutomaticPrices(limitAutomaticPrices).LimitManualPrices(limitManualPrices).Execute()



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
    fieldsAppPriceSchedules := []string{"FieldsAppPriceSchedules_example"} // []string | the fields to include for returned resources of type appPriceSchedules (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)
    fieldsAppPrices := []string{"FieldsAppPrices_example"} // []string | the fields to include for returned resources of type appPrices (optional)
    fieldsTerritories := []string{"FieldsTerritories_example"} // []string | the fields to include for returned resources of type territories (optional)
    limitAutomaticPrices := int32(56) // int32 | maximum number of related automaticPrices returned (when they are included) (optional)
    limitManualPrices := int32(56) // int32 | maximum number of related manualPrices returned (when they are included) (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppPriceSchedulesApi.AppPriceSchedulesGetInstance(context.Background(), id).FieldsAppPriceSchedules(fieldsAppPriceSchedules).Include(include).FieldsAppPrices(fieldsAppPrices).FieldsTerritories(fieldsTerritories).LimitAutomaticPrices(limitAutomaticPrices).LimitManualPrices(limitManualPrices).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppPriceSchedulesApi.AppPriceSchedulesGetInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppPriceSchedulesGetInstance`: AppPriceScheduleResponse
    fmt.Fprintf(os.Stdout, "Response from `AppPriceSchedulesApi.AppPriceSchedulesGetInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppPriceSchedulesGetInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsAppPriceSchedules** | **[]string** | the fields to include for returned resources of type appPriceSchedules | 
 **include** | **[]string** | comma-separated list of relationships to include | 
 **fieldsAppPrices** | **[]string** | the fields to include for returned resources of type appPrices | 
 **fieldsTerritories** | **[]string** | the fields to include for returned resources of type territories | 
 **limitAutomaticPrices** | **int32** | maximum number of related automaticPrices returned (when they are included) | 
 **limitManualPrices** | **int32** | maximum number of related manualPrices returned (when they are included) | 

### Return type

[**AppPriceScheduleResponse**](AppPriceScheduleResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppPriceSchedulesManualPricesGetToManyRelated

> AppPricesV2Response AppPriceSchedulesManualPricesGetToManyRelated(ctx, id).FilterEndDate(filterEndDate).FilterStartDate(filterStartDate).FilterTerritory(filterTerritory).FieldsAppPrices(fieldsAppPrices).FieldsAppPricePoints(fieldsAppPricePoints).FieldsTerritories(fieldsTerritories).Limit(limit).Include(include).Execute()



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
    filterEndDate := []string{"Inner_example"} // []string | filter by attribute 'endDate' (optional)
    filterStartDate := []string{"Inner_example"} // []string | filter by attribute 'startDate' (optional)
    filterTerritory := []string{"Inner_example"} // []string | filter by id(s) of related 'territory' (optional)
    fieldsAppPrices := []string{"FieldsAppPrices_example"} // []string | the fields to include for returned resources of type appPrices (optional)
    fieldsAppPricePoints := []string{"FieldsAppPricePoints_example"} // []string | the fields to include for returned resources of type appPricePoints (optional)
    fieldsTerritories := []string{"FieldsTerritories_example"} // []string | the fields to include for returned resources of type territories (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppPriceSchedulesApi.AppPriceSchedulesManualPricesGetToManyRelated(context.Background(), id).FilterEndDate(filterEndDate).FilterStartDate(filterStartDate).FilterTerritory(filterTerritory).FieldsAppPrices(fieldsAppPrices).FieldsAppPricePoints(fieldsAppPricePoints).FieldsTerritories(fieldsTerritories).Limit(limit).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppPriceSchedulesApi.AppPriceSchedulesManualPricesGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppPriceSchedulesManualPricesGetToManyRelated`: AppPricesV2Response
    fmt.Fprintf(os.Stdout, "Response from `AppPriceSchedulesApi.AppPriceSchedulesManualPricesGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppPriceSchedulesManualPricesGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **filterEndDate** | **[]string** | filter by attribute &#39;endDate&#39; | 
 **filterStartDate** | **[]string** | filter by attribute &#39;startDate&#39; | 
 **filterTerritory** | **[]string** | filter by id(s) of related &#39;territory&#39; | 
 **fieldsAppPrices** | **[]string** | the fields to include for returned resources of type appPrices | 
 **fieldsAppPricePoints** | **[]string** | the fields to include for returned resources of type appPricePoints | 
 **fieldsTerritories** | **[]string** | the fields to include for returned resources of type territories | 
 **limit** | **int32** | maximum resources per page | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**AppPricesV2Response**](AppPricesV2Response.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

