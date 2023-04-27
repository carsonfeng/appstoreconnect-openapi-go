# \CiXcodeVersionsApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**CiXcodeVersionsGetCollection**](CiXcodeVersionsApi.md#CiXcodeVersionsGetCollection) | **Get** /v1/ciXcodeVersions | 
[**CiXcodeVersionsGetInstance**](CiXcodeVersionsApi.md#CiXcodeVersionsGetInstance) | **Get** /v1/ciXcodeVersions/{id} | 
[**CiXcodeVersionsMacOsVersionsGetToManyRelated**](CiXcodeVersionsApi.md#CiXcodeVersionsMacOsVersionsGetToManyRelated) | **Get** /v1/ciXcodeVersions/{id}/macOsVersions | 



## CiXcodeVersionsGetCollection

> CiXcodeVersionsResponse CiXcodeVersionsGetCollection(ctx).FieldsCiXcodeVersions(fieldsCiXcodeVersions).Limit(limit).Include(include).FieldsCiMacOsVersions(fieldsCiMacOsVersions).LimitMacOsVersions(limitMacOsVersions).Execute()



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
    fieldsCiXcodeVersions := []string{"FieldsCiXcodeVersions_example"} // []string | the fields to include for returned resources of type ciXcodeVersions (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)
    fieldsCiMacOsVersions := []string{"FieldsCiMacOsVersions_example"} // []string | the fields to include for returned resources of type ciMacOsVersions (optional)
    limitMacOsVersions := int32(56) // int32 | maximum number of related macOsVersions returned (when they are included) (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.CiXcodeVersionsApi.CiXcodeVersionsGetCollection(context.Background()).FieldsCiXcodeVersions(fieldsCiXcodeVersions).Limit(limit).Include(include).FieldsCiMacOsVersions(fieldsCiMacOsVersions).LimitMacOsVersions(limitMacOsVersions).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `CiXcodeVersionsApi.CiXcodeVersionsGetCollection``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `CiXcodeVersionsGetCollection`: CiXcodeVersionsResponse
    fmt.Fprintf(os.Stdout, "Response from `CiXcodeVersionsApi.CiXcodeVersionsGetCollection`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiCiXcodeVersionsGetCollectionRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **fieldsCiXcodeVersions** | **[]string** | the fields to include for returned resources of type ciXcodeVersions | 
 **limit** | **int32** | maximum resources per page | 
 **include** | **[]string** | comma-separated list of relationships to include | 
 **fieldsCiMacOsVersions** | **[]string** | the fields to include for returned resources of type ciMacOsVersions | 
 **limitMacOsVersions** | **int32** | maximum number of related macOsVersions returned (when they are included) | 

### Return type

[**CiXcodeVersionsResponse**](CiXcodeVersionsResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## CiXcodeVersionsGetInstance

> CiXcodeVersionResponse CiXcodeVersionsGetInstance(ctx, id).FieldsCiXcodeVersions(fieldsCiXcodeVersions).Include(include).FieldsCiMacOsVersions(fieldsCiMacOsVersions).LimitMacOsVersions(limitMacOsVersions).Execute()



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
    fieldsCiXcodeVersions := []string{"FieldsCiXcodeVersions_example"} // []string | the fields to include for returned resources of type ciXcodeVersions (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)
    fieldsCiMacOsVersions := []string{"FieldsCiMacOsVersions_example"} // []string | the fields to include for returned resources of type ciMacOsVersions (optional)
    limitMacOsVersions := int32(56) // int32 | maximum number of related macOsVersions returned (when they are included) (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.CiXcodeVersionsApi.CiXcodeVersionsGetInstance(context.Background(), id).FieldsCiXcodeVersions(fieldsCiXcodeVersions).Include(include).FieldsCiMacOsVersions(fieldsCiMacOsVersions).LimitMacOsVersions(limitMacOsVersions).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `CiXcodeVersionsApi.CiXcodeVersionsGetInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `CiXcodeVersionsGetInstance`: CiXcodeVersionResponse
    fmt.Fprintf(os.Stdout, "Response from `CiXcodeVersionsApi.CiXcodeVersionsGetInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiCiXcodeVersionsGetInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsCiXcodeVersions** | **[]string** | the fields to include for returned resources of type ciXcodeVersions | 
 **include** | **[]string** | comma-separated list of relationships to include | 
 **fieldsCiMacOsVersions** | **[]string** | the fields to include for returned resources of type ciMacOsVersions | 
 **limitMacOsVersions** | **int32** | maximum number of related macOsVersions returned (when they are included) | 

### Return type

[**CiXcodeVersionResponse**](CiXcodeVersionResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## CiXcodeVersionsMacOsVersionsGetToManyRelated

> CiMacOsVersionsResponse CiXcodeVersionsMacOsVersionsGetToManyRelated(ctx, id).FieldsCiXcodeVersions(fieldsCiXcodeVersions).FieldsCiMacOsVersions(fieldsCiMacOsVersions).Limit(limit).LimitXcodeVersions(limitXcodeVersions).Include(include).Execute()



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
    fieldsCiXcodeVersions := []string{"FieldsCiXcodeVersions_example"} // []string | the fields to include for returned resources of type ciXcodeVersions (optional)
    fieldsCiMacOsVersions := []string{"FieldsCiMacOsVersions_example"} // []string | the fields to include for returned resources of type ciMacOsVersions (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    limitXcodeVersions := int32(56) // int32 | maximum number of related xcodeVersions returned (when they are included) (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.CiXcodeVersionsApi.CiXcodeVersionsMacOsVersionsGetToManyRelated(context.Background(), id).FieldsCiXcodeVersions(fieldsCiXcodeVersions).FieldsCiMacOsVersions(fieldsCiMacOsVersions).Limit(limit).LimitXcodeVersions(limitXcodeVersions).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `CiXcodeVersionsApi.CiXcodeVersionsMacOsVersionsGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `CiXcodeVersionsMacOsVersionsGetToManyRelated`: CiMacOsVersionsResponse
    fmt.Fprintf(os.Stdout, "Response from `CiXcodeVersionsApi.CiXcodeVersionsMacOsVersionsGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiCiXcodeVersionsMacOsVersionsGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsCiXcodeVersions** | **[]string** | the fields to include for returned resources of type ciXcodeVersions | 
 **fieldsCiMacOsVersions** | **[]string** | the fields to include for returned resources of type ciMacOsVersions | 
 **limit** | **int32** | maximum resources per page | 
 **limitXcodeVersions** | **int32** | maximum number of related xcodeVersions returned (when they are included) | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**CiMacOsVersionsResponse**](CiMacOsVersionsResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

