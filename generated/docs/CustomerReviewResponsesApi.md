# \CustomerReviewResponsesApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**CustomerReviewResponsesCreateInstance**](CustomerReviewResponsesApi.md#CustomerReviewResponsesCreateInstance) | **Post** /v1/customerReviewResponses | 
[**CustomerReviewResponsesDeleteInstance**](CustomerReviewResponsesApi.md#CustomerReviewResponsesDeleteInstance) | **Delete** /v1/customerReviewResponses/{id} | 
[**CustomerReviewResponsesGetInstance**](CustomerReviewResponsesApi.md#CustomerReviewResponsesGetInstance) | **Get** /v1/customerReviewResponses/{id} | 



## CustomerReviewResponsesCreateInstance

> CustomerReviewResponseV1Response CustomerReviewResponsesCreateInstance(ctx).CustomerReviewResponseV1CreateRequest(customerReviewResponseV1CreateRequest).Execute()



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
    customerReviewResponseV1CreateRequest := *openapiclient.NewCustomerReviewResponseV1CreateRequest(*openapiclient.NewCustomerReviewResponseV1CreateRequestData("Type_example", *openapiclient.NewCustomerReviewResponseV1CreateRequestDataAttributes("ResponseBody_example"), *openapiclient.NewCustomerReviewResponseV1CreateRequestDataRelationships(*openapiclient.NewCustomerReviewResponseV1CreateRequestDataRelationshipsReview(*openapiclient.NewCustomerReviewResponseV1RelationshipsReviewData("Type_example", "Id_example"))))) // CustomerReviewResponseV1CreateRequest | CustomerReviewResponse representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.CustomerReviewResponsesApi.CustomerReviewResponsesCreateInstance(context.Background()).CustomerReviewResponseV1CreateRequest(customerReviewResponseV1CreateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `CustomerReviewResponsesApi.CustomerReviewResponsesCreateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `CustomerReviewResponsesCreateInstance`: CustomerReviewResponseV1Response
    fmt.Fprintf(os.Stdout, "Response from `CustomerReviewResponsesApi.CustomerReviewResponsesCreateInstance`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiCustomerReviewResponsesCreateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **customerReviewResponseV1CreateRequest** | [**CustomerReviewResponseV1CreateRequest**](CustomerReviewResponseV1CreateRequest.md) | CustomerReviewResponse representation | 

### Return type

[**CustomerReviewResponseV1Response**](CustomerReviewResponseV1Response.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## CustomerReviewResponsesDeleteInstance

> CustomerReviewResponsesDeleteInstance(ctx, id).Execute()



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
    r, err := apiClient.CustomerReviewResponsesApi.CustomerReviewResponsesDeleteInstance(context.Background(), id).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `CustomerReviewResponsesApi.CustomerReviewResponsesDeleteInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiCustomerReviewResponsesDeleteInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------


### Return type

 (empty response body)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## CustomerReviewResponsesGetInstance

> CustomerReviewResponseV1Response CustomerReviewResponsesGetInstance(ctx, id).FieldsCustomerReviewResponses(fieldsCustomerReviewResponses).Include(include).Execute()



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
    fieldsCustomerReviewResponses := []string{"FieldsCustomerReviewResponses_example"} // []string | the fields to include for returned resources of type customerReviewResponses (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.CustomerReviewResponsesApi.CustomerReviewResponsesGetInstance(context.Background(), id).FieldsCustomerReviewResponses(fieldsCustomerReviewResponses).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `CustomerReviewResponsesApi.CustomerReviewResponsesGetInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `CustomerReviewResponsesGetInstance`: CustomerReviewResponseV1Response
    fmt.Fprintf(os.Stdout, "Response from `CustomerReviewResponsesApi.CustomerReviewResponsesGetInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiCustomerReviewResponsesGetInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsCustomerReviewResponses** | **[]string** | the fields to include for returned resources of type customerReviewResponses | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**CustomerReviewResponseV1Response**](CustomerReviewResponseV1Response.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

