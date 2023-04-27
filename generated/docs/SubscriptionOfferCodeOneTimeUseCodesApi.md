# \SubscriptionOfferCodeOneTimeUseCodesApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**SubscriptionOfferCodeOneTimeUseCodesCreateInstance**](SubscriptionOfferCodeOneTimeUseCodesApi.md#SubscriptionOfferCodeOneTimeUseCodesCreateInstance) | **Post** /v1/subscriptionOfferCodeOneTimeUseCodes | 
[**SubscriptionOfferCodeOneTimeUseCodesGetInstance**](SubscriptionOfferCodeOneTimeUseCodesApi.md#SubscriptionOfferCodeOneTimeUseCodesGetInstance) | **Get** /v1/subscriptionOfferCodeOneTimeUseCodes/{id} | 
[**SubscriptionOfferCodeOneTimeUseCodesUpdateInstance**](SubscriptionOfferCodeOneTimeUseCodesApi.md#SubscriptionOfferCodeOneTimeUseCodesUpdateInstance) | **Patch** /v1/subscriptionOfferCodeOneTimeUseCodes/{id} | 
[**SubscriptionOfferCodeOneTimeUseCodesValuesGetToOneRelated**](SubscriptionOfferCodeOneTimeUseCodesApi.md#SubscriptionOfferCodeOneTimeUseCodesValuesGetToOneRelated) | **Get** /v1/subscriptionOfferCodeOneTimeUseCodes/{id}/values | 



## SubscriptionOfferCodeOneTimeUseCodesCreateInstance

> SubscriptionOfferCodeOneTimeUseCodeResponse SubscriptionOfferCodeOneTimeUseCodesCreateInstance(ctx).SubscriptionOfferCodeOneTimeUseCodeCreateRequest(subscriptionOfferCodeOneTimeUseCodeCreateRequest).Execute()



### Example

```go
package main

import (
    "context"
    "fmt"
    "os"
    "time"
    openapiclient "github.com/GIT_USER_ID/GIT_REPO_ID"
)

func main() {
    subscriptionOfferCodeOneTimeUseCodeCreateRequest := *openapiclient.NewSubscriptionOfferCodeOneTimeUseCodeCreateRequest(*openapiclient.NewSubscriptionOfferCodeOneTimeUseCodeCreateRequestData("Type_example", *openapiclient.NewSubscriptionOfferCodeOneTimeUseCodeCreateRequestDataAttributes(int32(123), time.Now()), *openapiclient.NewSubscriptionOfferCodeCustomCodeCreateRequestDataRelationships(*openapiclient.NewSubscriptionOfferCodeCustomCodeCreateRequestDataRelationshipsOfferCode(*openapiclient.NewSubscriptionOfferCodeCustomCodeRelationshipsOfferCodeData("Type_example", "Id_example"))))) // SubscriptionOfferCodeOneTimeUseCodeCreateRequest | SubscriptionOfferCodeOneTimeUseCode representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.SubscriptionOfferCodeOneTimeUseCodesApi.SubscriptionOfferCodeOneTimeUseCodesCreateInstance(context.Background()).SubscriptionOfferCodeOneTimeUseCodeCreateRequest(subscriptionOfferCodeOneTimeUseCodeCreateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `SubscriptionOfferCodeOneTimeUseCodesApi.SubscriptionOfferCodeOneTimeUseCodesCreateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `SubscriptionOfferCodeOneTimeUseCodesCreateInstance`: SubscriptionOfferCodeOneTimeUseCodeResponse
    fmt.Fprintf(os.Stdout, "Response from `SubscriptionOfferCodeOneTimeUseCodesApi.SubscriptionOfferCodeOneTimeUseCodesCreateInstance`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiSubscriptionOfferCodeOneTimeUseCodesCreateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **subscriptionOfferCodeOneTimeUseCodeCreateRequest** | [**SubscriptionOfferCodeOneTimeUseCodeCreateRequest**](SubscriptionOfferCodeOneTimeUseCodeCreateRequest.md) | SubscriptionOfferCodeOneTimeUseCode representation | 

### Return type

[**SubscriptionOfferCodeOneTimeUseCodeResponse**](SubscriptionOfferCodeOneTimeUseCodeResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## SubscriptionOfferCodeOneTimeUseCodesGetInstance

> SubscriptionOfferCodeOneTimeUseCodeResponse SubscriptionOfferCodeOneTimeUseCodesGetInstance(ctx, id).FieldsSubscriptionOfferCodeOneTimeUseCodes(fieldsSubscriptionOfferCodeOneTimeUseCodes).Include(include).FieldsSubscriptionOfferCodeOneTimeUseCodeValues(fieldsSubscriptionOfferCodeOneTimeUseCodeValues).Execute()



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
    fieldsSubscriptionOfferCodeOneTimeUseCodes := []string{"FieldsSubscriptionOfferCodeOneTimeUseCodes_example"} // []string | the fields to include for returned resources of type subscriptionOfferCodeOneTimeUseCodes (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)
    fieldsSubscriptionOfferCodeOneTimeUseCodeValues := []string{"Inner_example"} // []string | the fields to include for returned resources of type subscriptionOfferCodeOneTimeUseCodeValues (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.SubscriptionOfferCodeOneTimeUseCodesApi.SubscriptionOfferCodeOneTimeUseCodesGetInstance(context.Background(), id).FieldsSubscriptionOfferCodeOneTimeUseCodes(fieldsSubscriptionOfferCodeOneTimeUseCodes).Include(include).FieldsSubscriptionOfferCodeOneTimeUseCodeValues(fieldsSubscriptionOfferCodeOneTimeUseCodeValues).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `SubscriptionOfferCodeOneTimeUseCodesApi.SubscriptionOfferCodeOneTimeUseCodesGetInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `SubscriptionOfferCodeOneTimeUseCodesGetInstance`: SubscriptionOfferCodeOneTimeUseCodeResponse
    fmt.Fprintf(os.Stdout, "Response from `SubscriptionOfferCodeOneTimeUseCodesApi.SubscriptionOfferCodeOneTimeUseCodesGetInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiSubscriptionOfferCodeOneTimeUseCodesGetInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsSubscriptionOfferCodeOneTimeUseCodes** | **[]string** | the fields to include for returned resources of type subscriptionOfferCodeOneTimeUseCodes | 
 **include** | **[]string** | comma-separated list of relationships to include | 
 **fieldsSubscriptionOfferCodeOneTimeUseCodeValues** | **[]string** | the fields to include for returned resources of type subscriptionOfferCodeOneTimeUseCodeValues | 

### Return type

[**SubscriptionOfferCodeOneTimeUseCodeResponse**](SubscriptionOfferCodeOneTimeUseCodeResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## SubscriptionOfferCodeOneTimeUseCodesUpdateInstance

> SubscriptionOfferCodeOneTimeUseCodeResponse SubscriptionOfferCodeOneTimeUseCodesUpdateInstance(ctx, id).SubscriptionOfferCodeOneTimeUseCodeUpdateRequest(subscriptionOfferCodeOneTimeUseCodeUpdateRequest).Execute()



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
    subscriptionOfferCodeOneTimeUseCodeUpdateRequest := *openapiclient.NewSubscriptionOfferCodeOneTimeUseCodeUpdateRequest(*openapiclient.NewSubscriptionOfferCodeOneTimeUseCodeUpdateRequestData("Type_example", "Id_example")) // SubscriptionOfferCodeOneTimeUseCodeUpdateRequest | SubscriptionOfferCodeOneTimeUseCode representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.SubscriptionOfferCodeOneTimeUseCodesApi.SubscriptionOfferCodeOneTimeUseCodesUpdateInstance(context.Background(), id).SubscriptionOfferCodeOneTimeUseCodeUpdateRequest(subscriptionOfferCodeOneTimeUseCodeUpdateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `SubscriptionOfferCodeOneTimeUseCodesApi.SubscriptionOfferCodeOneTimeUseCodesUpdateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `SubscriptionOfferCodeOneTimeUseCodesUpdateInstance`: SubscriptionOfferCodeOneTimeUseCodeResponse
    fmt.Fprintf(os.Stdout, "Response from `SubscriptionOfferCodeOneTimeUseCodesApi.SubscriptionOfferCodeOneTimeUseCodesUpdateInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiSubscriptionOfferCodeOneTimeUseCodesUpdateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **subscriptionOfferCodeOneTimeUseCodeUpdateRequest** | [**SubscriptionOfferCodeOneTimeUseCodeUpdateRequest**](SubscriptionOfferCodeOneTimeUseCodeUpdateRequest.md) | SubscriptionOfferCodeOneTimeUseCode representation | 

### Return type

[**SubscriptionOfferCodeOneTimeUseCodeResponse**](SubscriptionOfferCodeOneTimeUseCodeResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## SubscriptionOfferCodeOneTimeUseCodesValuesGetToOneRelated

> string SubscriptionOfferCodeOneTimeUseCodesValuesGetToOneRelated(ctx, id).Execute()



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
    resp, r, err := apiClient.SubscriptionOfferCodeOneTimeUseCodesApi.SubscriptionOfferCodeOneTimeUseCodesValuesGetToOneRelated(context.Background(), id).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `SubscriptionOfferCodeOneTimeUseCodesApi.SubscriptionOfferCodeOneTimeUseCodesValuesGetToOneRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `SubscriptionOfferCodeOneTimeUseCodesValuesGetToOneRelated`: string
    fmt.Fprintf(os.Stdout, "Response from `SubscriptionOfferCodeOneTimeUseCodesApi.SubscriptionOfferCodeOneTimeUseCodesValuesGetToOneRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiSubscriptionOfferCodeOneTimeUseCodesValuesGetToOneRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------


### Return type

**string**

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json, text/csv

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

