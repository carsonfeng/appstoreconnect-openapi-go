# \InAppPurchaseAvailabilitiesApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**InAppPurchaseAvailabilitiesAvailableTerritoriesGetToManyRelated**](InAppPurchaseAvailabilitiesApi.md#InAppPurchaseAvailabilitiesAvailableTerritoriesGetToManyRelated) | **Get** /v1/inAppPurchaseAvailabilities/{id}/availableTerritories | 
[**InAppPurchaseAvailabilitiesCreateInstance**](InAppPurchaseAvailabilitiesApi.md#InAppPurchaseAvailabilitiesCreateInstance) | **Post** /v1/inAppPurchaseAvailabilities | 
[**InAppPurchaseAvailabilitiesGetInstance**](InAppPurchaseAvailabilitiesApi.md#InAppPurchaseAvailabilitiesGetInstance) | **Get** /v1/inAppPurchaseAvailabilities/{id} | 



## InAppPurchaseAvailabilitiesAvailableTerritoriesGetToManyRelated

> TerritoriesResponse InAppPurchaseAvailabilitiesAvailableTerritoriesGetToManyRelated(ctx, id).FieldsTerritories(fieldsTerritories).Limit(limit).Execute()



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
    resp, r, err := apiClient.InAppPurchaseAvailabilitiesApi.InAppPurchaseAvailabilitiesAvailableTerritoriesGetToManyRelated(context.Background(), id).FieldsTerritories(fieldsTerritories).Limit(limit).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `InAppPurchaseAvailabilitiesApi.InAppPurchaseAvailabilitiesAvailableTerritoriesGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `InAppPurchaseAvailabilitiesAvailableTerritoriesGetToManyRelated`: TerritoriesResponse
    fmt.Fprintf(os.Stdout, "Response from `InAppPurchaseAvailabilitiesApi.InAppPurchaseAvailabilitiesAvailableTerritoriesGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiInAppPurchaseAvailabilitiesAvailableTerritoriesGetToManyRelatedRequest struct via the builder pattern


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


## InAppPurchaseAvailabilitiesCreateInstance

> InAppPurchaseAvailabilityResponse InAppPurchaseAvailabilitiesCreateInstance(ctx).InAppPurchaseAvailabilityCreateRequest(inAppPurchaseAvailabilityCreateRequest).Execute()



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
    inAppPurchaseAvailabilityCreateRequest := *openapiclient.NewInAppPurchaseAvailabilityCreateRequest(*openapiclient.NewInAppPurchaseAvailabilityCreateRequestData("Type_example", *openapiclient.NewAppAvailabilityCreateRequestDataAttributes(false), *openapiclient.NewInAppPurchaseAvailabilityCreateRequestDataRelationships(*openapiclient.NewInAppPurchaseAppStoreReviewScreenshotCreateRequestDataRelationshipsInAppPurchaseV2(*openapiclient.NewAppRelationshipsInAppPurchasesDataInner("Type_example", "Id_example")), *openapiclient.NewAppAvailabilityCreateRequestDataRelationshipsAvailableTerritories([]openapiclient.AppAvailabilityRelationshipsAvailableTerritoriesDataInner{*openapiclient.NewAppAvailabilityRelationshipsAvailableTerritoriesDataInner("Type_example", "Id_example")})))) // InAppPurchaseAvailabilityCreateRequest | InAppPurchaseAvailability representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.InAppPurchaseAvailabilitiesApi.InAppPurchaseAvailabilitiesCreateInstance(context.Background()).InAppPurchaseAvailabilityCreateRequest(inAppPurchaseAvailabilityCreateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `InAppPurchaseAvailabilitiesApi.InAppPurchaseAvailabilitiesCreateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `InAppPurchaseAvailabilitiesCreateInstance`: InAppPurchaseAvailabilityResponse
    fmt.Fprintf(os.Stdout, "Response from `InAppPurchaseAvailabilitiesApi.InAppPurchaseAvailabilitiesCreateInstance`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiInAppPurchaseAvailabilitiesCreateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **inAppPurchaseAvailabilityCreateRequest** | [**InAppPurchaseAvailabilityCreateRequest**](InAppPurchaseAvailabilityCreateRequest.md) | InAppPurchaseAvailability representation | 

### Return type

[**InAppPurchaseAvailabilityResponse**](InAppPurchaseAvailabilityResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## InAppPurchaseAvailabilitiesGetInstance

> InAppPurchaseAvailabilityResponse InAppPurchaseAvailabilitiesGetInstance(ctx, id).FieldsInAppPurchaseAvailabilities(fieldsInAppPurchaseAvailabilities).Include(include).FieldsTerritories(fieldsTerritories).LimitAvailableTerritories(limitAvailableTerritories).Execute()



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
    fieldsInAppPurchaseAvailabilities := []string{"FieldsInAppPurchaseAvailabilities_example"} // []string | the fields to include for returned resources of type inAppPurchaseAvailabilities (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)
    fieldsTerritories := []string{"FieldsTerritories_example"} // []string | the fields to include for returned resources of type territories (optional)
    limitAvailableTerritories := int32(56) // int32 | maximum number of related availableTerritories returned (when they are included) (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.InAppPurchaseAvailabilitiesApi.InAppPurchaseAvailabilitiesGetInstance(context.Background(), id).FieldsInAppPurchaseAvailabilities(fieldsInAppPurchaseAvailabilities).Include(include).FieldsTerritories(fieldsTerritories).LimitAvailableTerritories(limitAvailableTerritories).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `InAppPurchaseAvailabilitiesApi.InAppPurchaseAvailabilitiesGetInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `InAppPurchaseAvailabilitiesGetInstance`: InAppPurchaseAvailabilityResponse
    fmt.Fprintf(os.Stdout, "Response from `InAppPurchaseAvailabilitiesApi.InAppPurchaseAvailabilitiesGetInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiInAppPurchaseAvailabilitiesGetInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsInAppPurchaseAvailabilities** | **[]string** | the fields to include for returned resources of type inAppPurchaseAvailabilities | 
 **include** | **[]string** | comma-separated list of relationships to include | 
 **fieldsTerritories** | **[]string** | the fields to include for returned resources of type territories | 
 **limitAvailableTerritories** | **int32** | maximum number of related availableTerritories returned (when they are included) | 

### Return type

[**InAppPurchaseAvailabilityResponse**](InAppPurchaseAvailabilityResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

