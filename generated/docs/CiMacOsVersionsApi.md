# \CiMacOsVersionsApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**CiMacOsVersionsGetCollection**](CiMacOsVersionsApi.md#CiMacOsVersionsGetCollection) | **Get** /v1/ciMacOsVersions | 
[**CiMacOsVersionsGetInstance**](CiMacOsVersionsApi.md#CiMacOsVersionsGetInstance) | **Get** /v1/ciMacOsVersions/{id} | 
[**CiMacOsVersionsXcodeVersionsGetToManyRelated**](CiMacOsVersionsApi.md#CiMacOsVersionsXcodeVersionsGetToManyRelated) | **Get** /v1/ciMacOsVersions/{id}/xcodeVersions | 



## CiMacOsVersionsGetCollection

> CiMacOsVersionsResponse CiMacOsVersionsGetCollection(ctx).FieldsCiMacOsVersions(fieldsCiMacOsVersions).Limit(limit).Include(include).FieldsCiXcodeVersions(fieldsCiXcodeVersions).LimitXcodeVersions(limitXcodeVersions).Execute()



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
    fieldsCiMacOsVersions := []string{"FieldsCiMacOsVersions_example"} // []string | the fields to include for returned resources of type ciMacOsVersions (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)
    fieldsCiXcodeVersions := []string{"FieldsCiXcodeVersions_example"} // []string | the fields to include for returned resources of type ciXcodeVersions (optional)
    limitXcodeVersions := int32(56) // int32 | maximum number of related xcodeVersions returned (when they are included) (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.CiMacOsVersionsApi.CiMacOsVersionsGetCollection(context.Background()).FieldsCiMacOsVersions(fieldsCiMacOsVersions).Limit(limit).Include(include).FieldsCiXcodeVersions(fieldsCiXcodeVersions).LimitXcodeVersions(limitXcodeVersions).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `CiMacOsVersionsApi.CiMacOsVersionsGetCollection``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `CiMacOsVersionsGetCollection`: CiMacOsVersionsResponse
    fmt.Fprintf(os.Stdout, "Response from `CiMacOsVersionsApi.CiMacOsVersionsGetCollection`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiCiMacOsVersionsGetCollectionRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **fieldsCiMacOsVersions** | **[]string** | the fields to include for returned resources of type ciMacOsVersions | 
 **limit** | **int32** | maximum resources per page | 
 **include** | **[]string** | comma-separated list of relationships to include | 
 **fieldsCiXcodeVersions** | **[]string** | the fields to include for returned resources of type ciXcodeVersions | 
 **limitXcodeVersions** | **int32** | maximum number of related xcodeVersions returned (when they are included) | 

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


## CiMacOsVersionsGetInstance

> CiMacOsVersionResponse CiMacOsVersionsGetInstance(ctx, id).FieldsCiMacOsVersions(fieldsCiMacOsVersions).Include(include).FieldsCiXcodeVersions(fieldsCiXcodeVersions).LimitXcodeVersions(limitXcodeVersions).Execute()



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
    fieldsCiMacOsVersions := []string{"FieldsCiMacOsVersions_example"} // []string | the fields to include for returned resources of type ciMacOsVersions (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)
    fieldsCiXcodeVersions := []string{"FieldsCiXcodeVersions_example"} // []string | the fields to include for returned resources of type ciXcodeVersions (optional)
    limitXcodeVersions := int32(56) // int32 | maximum number of related xcodeVersions returned (when they are included) (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.CiMacOsVersionsApi.CiMacOsVersionsGetInstance(context.Background(), id).FieldsCiMacOsVersions(fieldsCiMacOsVersions).Include(include).FieldsCiXcodeVersions(fieldsCiXcodeVersions).LimitXcodeVersions(limitXcodeVersions).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `CiMacOsVersionsApi.CiMacOsVersionsGetInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `CiMacOsVersionsGetInstance`: CiMacOsVersionResponse
    fmt.Fprintf(os.Stdout, "Response from `CiMacOsVersionsApi.CiMacOsVersionsGetInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiCiMacOsVersionsGetInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsCiMacOsVersions** | **[]string** | the fields to include for returned resources of type ciMacOsVersions | 
 **include** | **[]string** | comma-separated list of relationships to include | 
 **fieldsCiXcodeVersions** | **[]string** | the fields to include for returned resources of type ciXcodeVersions | 
 **limitXcodeVersions** | **int32** | maximum number of related xcodeVersions returned (when they are included) | 

### Return type

[**CiMacOsVersionResponse**](CiMacOsVersionResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## CiMacOsVersionsXcodeVersionsGetToManyRelated

> CiXcodeVersionsResponse CiMacOsVersionsXcodeVersionsGetToManyRelated(ctx, id).FieldsCiXcodeVersions(fieldsCiXcodeVersions).FieldsCiMacOsVersions(fieldsCiMacOsVersions).Limit(limit).LimitMacOsVersions(limitMacOsVersions).Include(include).Execute()



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
    limitMacOsVersions := int32(56) // int32 | maximum number of related macOsVersions returned (when they are included) (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.CiMacOsVersionsApi.CiMacOsVersionsXcodeVersionsGetToManyRelated(context.Background(), id).FieldsCiXcodeVersions(fieldsCiXcodeVersions).FieldsCiMacOsVersions(fieldsCiMacOsVersions).Limit(limit).LimitMacOsVersions(limitMacOsVersions).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `CiMacOsVersionsApi.CiMacOsVersionsXcodeVersionsGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `CiMacOsVersionsXcodeVersionsGetToManyRelated`: CiXcodeVersionsResponse
    fmt.Fprintf(os.Stdout, "Response from `CiMacOsVersionsApi.CiMacOsVersionsXcodeVersionsGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiCiMacOsVersionsXcodeVersionsGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsCiXcodeVersions** | **[]string** | the fields to include for returned resources of type ciXcodeVersions | 
 **fieldsCiMacOsVersions** | **[]string** | the fields to include for returned resources of type ciMacOsVersions | 
 **limit** | **int32** | maximum resources per page | 
 **limitMacOsVersions** | **int32** | maximum number of related macOsVersions returned (when they are included) | 
 **include** | **[]string** | comma-separated list of relationships to include | 

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

