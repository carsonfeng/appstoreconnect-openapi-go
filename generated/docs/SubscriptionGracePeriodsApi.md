# \SubscriptionGracePeriodsApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**SubscriptionGracePeriodsGetInstance**](SubscriptionGracePeriodsApi.md#SubscriptionGracePeriodsGetInstance) | **Get** /v1/subscriptionGracePeriods/{id} | 
[**SubscriptionGracePeriodsUpdateInstance**](SubscriptionGracePeriodsApi.md#SubscriptionGracePeriodsUpdateInstance) | **Patch** /v1/subscriptionGracePeriods/{id} | 



## SubscriptionGracePeriodsGetInstance

> SubscriptionGracePeriodResponse SubscriptionGracePeriodsGetInstance(ctx, id).FieldsSubscriptionGracePeriods(fieldsSubscriptionGracePeriods).Execute()



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
    fieldsSubscriptionGracePeriods := []string{"FieldsSubscriptionGracePeriods_example"} // []string | the fields to include for returned resources of type subscriptionGracePeriods (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.SubscriptionGracePeriodsApi.SubscriptionGracePeriodsGetInstance(context.Background(), id).FieldsSubscriptionGracePeriods(fieldsSubscriptionGracePeriods).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `SubscriptionGracePeriodsApi.SubscriptionGracePeriodsGetInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `SubscriptionGracePeriodsGetInstance`: SubscriptionGracePeriodResponse
    fmt.Fprintf(os.Stdout, "Response from `SubscriptionGracePeriodsApi.SubscriptionGracePeriodsGetInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiSubscriptionGracePeriodsGetInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsSubscriptionGracePeriods** | **[]string** | the fields to include for returned resources of type subscriptionGracePeriods | 

### Return type

[**SubscriptionGracePeriodResponse**](SubscriptionGracePeriodResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## SubscriptionGracePeriodsUpdateInstance

> SubscriptionGracePeriodResponse SubscriptionGracePeriodsUpdateInstance(ctx, id).SubscriptionGracePeriodUpdateRequest(subscriptionGracePeriodUpdateRequest).Execute()



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
    subscriptionGracePeriodUpdateRequest := *openapiclient.NewSubscriptionGracePeriodUpdateRequest(*openapiclient.NewSubscriptionGracePeriodUpdateRequestData("Type_example", "Id_example")) // SubscriptionGracePeriodUpdateRequest | SubscriptionGracePeriod representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.SubscriptionGracePeriodsApi.SubscriptionGracePeriodsUpdateInstance(context.Background(), id).SubscriptionGracePeriodUpdateRequest(subscriptionGracePeriodUpdateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `SubscriptionGracePeriodsApi.SubscriptionGracePeriodsUpdateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `SubscriptionGracePeriodsUpdateInstance`: SubscriptionGracePeriodResponse
    fmt.Fprintf(os.Stdout, "Response from `SubscriptionGracePeriodsApi.SubscriptionGracePeriodsUpdateInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiSubscriptionGracePeriodsUpdateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **subscriptionGracePeriodUpdateRequest** | [**SubscriptionGracePeriodUpdateRequest**](SubscriptionGracePeriodUpdateRequest.md) | SubscriptionGracePeriod representation | 

### Return type

[**SubscriptionGracePeriodResponse**](SubscriptionGracePeriodResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

