# \AppAvailabilitiesApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**AppAvailabilitiesAvailableTerritoriesGetToManyRelated**](AppAvailabilitiesApi.md#AppAvailabilitiesAvailableTerritoriesGetToManyRelated) | **Get** /v1/appAvailabilities/{id}/availableTerritories | 
[**AppAvailabilitiesCreateInstance**](AppAvailabilitiesApi.md#AppAvailabilitiesCreateInstance) | **Post** /v1/appAvailabilities | 
[**AppAvailabilitiesGetInstance**](AppAvailabilitiesApi.md#AppAvailabilitiesGetInstance) | **Get** /v1/appAvailabilities/{id} | 



## AppAvailabilitiesAvailableTerritoriesGetToManyRelated

> TerritoriesResponse AppAvailabilitiesAvailableTerritoriesGetToManyRelated(ctx, id).FieldsTerritories(fieldsTerritories).Limit(limit).Execute()



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
    limit := int32(56) // int32 | maximum resources per page (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppAvailabilitiesApi.AppAvailabilitiesAvailableTerritoriesGetToManyRelated(context.Background(), id).FieldsTerritories(fieldsTerritories).Limit(limit).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppAvailabilitiesApi.AppAvailabilitiesAvailableTerritoriesGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppAvailabilitiesAvailableTerritoriesGetToManyRelated`: TerritoriesResponse
    fmt.Fprintf(os.Stdout, "Response from `AppAvailabilitiesApi.AppAvailabilitiesAvailableTerritoriesGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppAvailabilitiesAvailableTerritoriesGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsTerritories** | **[]string** | the fields to include for returned resources of type territories | 
 **limit** | **int32** | maximum resources per page | 

### Return type

[**TerritoriesResponse**](TerritoriesResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppAvailabilitiesCreateInstance

> AppAvailabilityResponse AppAvailabilitiesCreateInstance(ctx).AppAvailabilityCreateRequest(appAvailabilityCreateRequest).Execute()



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
    appAvailabilityCreateRequest := *openapiclient.NewAppAvailabilityCreateRequest(*openapiclient.NewAppAvailabilityCreateRequestData("Type_example", *openapiclient.NewAppAvailabilityCreateRequestDataAttributes(false), *openapiclient.NewAppAvailabilityCreateRequestDataRelationships(*openapiclient.NewAppAvailabilityCreateRequestDataRelationshipsApp(*openapiclient.NewAppAvailabilityRelationshipsAppData("Type_example", "Id_example")), *openapiclient.NewAppAvailabilityCreateRequestDataRelationshipsAvailableTerritories([]openapiclient.AppAvailabilityRelationshipsAvailableTerritoriesDataInner{*openapiclient.NewAppAvailabilityRelationshipsAvailableTerritoriesDataInner("Type_example", "Id_example")})))) // AppAvailabilityCreateRequest | AppAvailability representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppAvailabilitiesApi.AppAvailabilitiesCreateInstance(context.Background()).AppAvailabilityCreateRequest(appAvailabilityCreateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppAvailabilitiesApi.AppAvailabilitiesCreateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppAvailabilitiesCreateInstance`: AppAvailabilityResponse
    fmt.Fprintf(os.Stdout, "Response from `AppAvailabilitiesApi.AppAvailabilitiesCreateInstance`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiAppAvailabilitiesCreateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **appAvailabilityCreateRequest** | [**AppAvailabilityCreateRequest**](AppAvailabilityCreateRequest.md) | AppAvailability representation | 

### Return type

[**AppAvailabilityResponse**](AppAvailabilityResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppAvailabilitiesGetInstance

> AppAvailabilityResponse AppAvailabilitiesGetInstance(ctx, id).FieldsAppAvailabilities(fieldsAppAvailabilities).Include(include).FieldsTerritories(fieldsTerritories).LimitAvailableTerritories(limitAvailableTerritories).Execute()



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
    fieldsAppAvailabilities := []string{"FieldsAppAvailabilities_example"} // []string | the fields to include for returned resources of type appAvailabilities (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)
    fieldsTerritories := []string{"FieldsTerritories_example"} // []string | the fields to include for returned resources of type territories (optional)
    limitAvailableTerritories := int32(56) // int32 | maximum number of related availableTerritories returned (when they are included) (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppAvailabilitiesApi.AppAvailabilitiesGetInstance(context.Background(), id).FieldsAppAvailabilities(fieldsAppAvailabilities).Include(include).FieldsTerritories(fieldsTerritories).LimitAvailableTerritories(limitAvailableTerritories).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppAvailabilitiesApi.AppAvailabilitiesGetInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppAvailabilitiesGetInstance`: AppAvailabilityResponse
    fmt.Fprintf(os.Stdout, "Response from `AppAvailabilitiesApi.AppAvailabilitiesGetInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppAvailabilitiesGetInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsAppAvailabilities** | **[]string** | the fields to include for returned resources of type appAvailabilities | 
 **include** | **[]string** | comma-separated list of relationships to include | 
 **fieldsTerritories** | **[]string** | the fields to include for returned resources of type territories | 
 **limitAvailableTerritories** | **int32** | maximum number of related availableTerritories returned (when they are included) | 

### Return type

[**AppAvailabilityResponse**](AppAvailabilityResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

