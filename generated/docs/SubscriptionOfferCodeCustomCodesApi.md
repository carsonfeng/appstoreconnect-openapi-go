# \SubscriptionOfferCodeCustomCodesApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**SubscriptionOfferCodeCustomCodesCreateInstance**](SubscriptionOfferCodeCustomCodesApi.md#SubscriptionOfferCodeCustomCodesCreateInstance) | **Post** /v1/subscriptionOfferCodeCustomCodes | 
[**SubscriptionOfferCodeCustomCodesGetInstance**](SubscriptionOfferCodeCustomCodesApi.md#SubscriptionOfferCodeCustomCodesGetInstance) | **Get** /v1/subscriptionOfferCodeCustomCodes/{id} | 
[**SubscriptionOfferCodeCustomCodesUpdateInstance**](SubscriptionOfferCodeCustomCodesApi.md#SubscriptionOfferCodeCustomCodesUpdateInstance) | **Patch** /v1/subscriptionOfferCodeCustomCodes/{id} | 



## SubscriptionOfferCodeCustomCodesCreateInstance

> SubscriptionOfferCodeCustomCodeResponse SubscriptionOfferCodeCustomCodesCreateInstance(ctx).SubscriptionOfferCodeCustomCodeCreateRequest(subscriptionOfferCodeCustomCodeCreateRequest).Execute()



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
    subscriptionOfferCodeCustomCodeCreateRequest := *openapiclient.NewSubscriptionOfferCodeCustomCodeCreateRequest(*openapiclient.NewSubscriptionOfferCodeCustomCodeCreateRequestData("Type_example", *openapiclient.NewSubscriptionOfferCodeCustomCodeCreateRequestDataAttributes("CustomCode_example", int32(123)), *openapiclient.NewSubscriptionOfferCodeCustomCodeCreateRequestDataRelationships(*openapiclient.NewSubscriptionOfferCodeCustomCodeCreateRequestDataRelationshipsOfferCode(*openapiclient.NewSubscriptionOfferCodeCustomCodeRelationshipsOfferCodeData("Type_example", "Id_example"))))) // SubscriptionOfferCodeCustomCodeCreateRequest | SubscriptionOfferCodeCustomCode representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.SubscriptionOfferCodeCustomCodesApi.SubscriptionOfferCodeCustomCodesCreateInstance(context.Background()).SubscriptionOfferCodeCustomCodeCreateRequest(subscriptionOfferCodeCustomCodeCreateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `SubscriptionOfferCodeCustomCodesApi.SubscriptionOfferCodeCustomCodesCreateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `SubscriptionOfferCodeCustomCodesCreateInstance`: SubscriptionOfferCodeCustomCodeResponse
    fmt.Fprintf(os.Stdout, "Response from `SubscriptionOfferCodeCustomCodesApi.SubscriptionOfferCodeCustomCodesCreateInstance`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiSubscriptionOfferCodeCustomCodesCreateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **subscriptionOfferCodeCustomCodeCreateRequest** | [**SubscriptionOfferCodeCustomCodeCreateRequest**](SubscriptionOfferCodeCustomCodeCreateRequest.md) | SubscriptionOfferCodeCustomCode representation | 

### Return type

[**SubscriptionOfferCodeCustomCodeResponse**](SubscriptionOfferCodeCustomCodeResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## SubscriptionOfferCodeCustomCodesGetInstance

> SubscriptionOfferCodeCustomCodeResponse SubscriptionOfferCodeCustomCodesGetInstance(ctx, id).FieldsSubscriptionOfferCodeCustomCodes(fieldsSubscriptionOfferCodeCustomCodes).Include(include).Execute()



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
    fieldsSubscriptionOfferCodeCustomCodes := []string{"FieldsSubscriptionOfferCodeCustomCodes_example"} // []string | the fields to include for returned resources of type subscriptionOfferCodeCustomCodes (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.SubscriptionOfferCodeCustomCodesApi.SubscriptionOfferCodeCustomCodesGetInstance(context.Background(), id).FieldsSubscriptionOfferCodeCustomCodes(fieldsSubscriptionOfferCodeCustomCodes).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `SubscriptionOfferCodeCustomCodesApi.SubscriptionOfferCodeCustomCodesGetInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `SubscriptionOfferCodeCustomCodesGetInstance`: SubscriptionOfferCodeCustomCodeResponse
    fmt.Fprintf(os.Stdout, "Response from `SubscriptionOfferCodeCustomCodesApi.SubscriptionOfferCodeCustomCodesGetInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiSubscriptionOfferCodeCustomCodesGetInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsSubscriptionOfferCodeCustomCodes** | **[]string** | the fields to include for returned resources of type subscriptionOfferCodeCustomCodes | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**SubscriptionOfferCodeCustomCodeResponse**](SubscriptionOfferCodeCustomCodeResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## SubscriptionOfferCodeCustomCodesUpdateInstance

> SubscriptionOfferCodeCustomCodeResponse SubscriptionOfferCodeCustomCodesUpdateInstance(ctx, id).SubscriptionOfferCodeCustomCodeUpdateRequest(subscriptionOfferCodeCustomCodeUpdateRequest).Execute()



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
    subscriptionOfferCodeCustomCodeUpdateRequest := *openapiclient.NewSubscriptionOfferCodeCustomCodeUpdateRequest(*openapiclient.NewSubscriptionOfferCodeCustomCodeUpdateRequestData("Type_example", "Id_example")) // SubscriptionOfferCodeCustomCodeUpdateRequest | SubscriptionOfferCodeCustomCode representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.SubscriptionOfferCodeCustomCodesApi.SubscriptionOfferCodeCustomCodesUpdateInstance(context.Background(), id).SubscriptionOfferCodeCustomCodeUpdateRequest(subscriptionOfferCodeCustomCodeUpdateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `SubscriptionOfferCodeCustomCodesApi.SubscriptionOfferCodeCustomCodesUpdateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `SubscriptionOfferCodeCustomCodesUpdateInstance`: SubscriptionOfferCodeCustomCodeResponse
    fmt.Fprintf(os.Stdout, "Response from `SubscriptionOfferCodeCustomCodesApi.SubscriptionOfferCodeCustomCodesUpdateInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiSubscriptionOfferCodeCustomCodesUpdateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **subscriptionOfferCodeCustomCodeUpdateRequest** | [**SubscriptionOfferCodeCustomCodeUpdateRequest**](SubscriptionOfferCodeCustomCodeUpdateRequest.md) | SubscriptionOfferCodeCustomCode representation | 

### Return type

[**SubscriptionOfferCodeCustomCodeResponse**](SubscriptionOfferCodeCustomCodeResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

