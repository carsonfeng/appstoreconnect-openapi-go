# \CustomerReviewsApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**CustomerReviewsGetInstance**](CustomerReviewsApi.md#CustomerReviewsGetInstance) | **Get** /v1/customerReviews/{id} | 
[**CustomerReviewsResponseGetToOneRelated**](CustomerReviewsApi.md#CustomerReviewsResponseGetToOneRelated) | **Get** /v1/customerReviews/{id}/response | 



## CustomerReviewsGetInstance

> CustomerReviewResponse CustomerReviewsGetInstance(ctx, id).FieldsCustomerReviews(fieldsCustomerReviews).Include(include).FieldsCustomerReviewResponses(fieldsCustomerReviewResponses).Execute()



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
    fieldsCustomerReviews := []string{"FieldsCustomerReviews_example"} // []string | the fields to include for returned resources of type customerReviews (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)
    fieldsCustomerReviewResponses := []string{"FieldsCustomerReviewResponses_example"} // []string | the fields to include for returned resources of type customerReviewResponses (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.CustomerReviewsApi.CustomerReviewsGetInstance(context.Background(), id).FieldsCustomerReviews(fieldsCustomerReviews).Include(include).FieldsCustomerReviewResponses(fieldsCustomerReviewResponses).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `CustomerReviewsApi.CustomerReviewsGetInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `CustomerReviewsGetInstance`: CustomerReviewResponse
    fmt.Fprintf(os.Stdout, "Response from `CustomerReviewsApi.CustomerReviewsGetInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiCustomerReviewsGetInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsCustomerReviews** | **[]string** | the fields to include for returned resources of type customerReviews | 
 **include** | **[]string** | comma-separated list of relationships to include | 
 **fieldsCustomerReviewResponses** | **[]string** | the fields to include for returned resources of type customerReviewResponses | 

### Return type

[**CustomerReviewResponse**](CustomerReviewResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## CustomerReviewsResponseGetToOneRelated

> CustomerReviewResponseV1Response CustomerReviewsResponseGetToOneRelated(ctx, id).FieldsCustomerReviews(fieldsCustomerReviews).FieldsCustomerReviewResponses(fieldsCustomerReviewResponses).Include(include).Execute()



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
    fieldsCustomerReviews := []string{"FieldsCustomerReviews_example"} // []string | the fields to include for returned resources of type customerReviews (optional)
    fieldsCustomerReviewResponses := []string{"FieldsCustomerReviewResponses_example"} // []string | the fields to include for returned resources of type customerReviewResponses (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.CustomerReviewsApi.CustomerReviewsResponseGetToOneRelated(context.Background(), id).FieldsCustomerReviews(fieldsCustomerReviews).FieldsCustomerReviewResponses(fieldsCustomerReviewResponses).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `CustomerReviewsApi.CustomerReviewsResponseGetToOneRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `CustomerReviewsResponseGetToOneRelated`: CustomerReviewResponseV1Response
    fmt.Fprintf(os.Stdout, "Response from `CustomerReviewsApi.CustomerReviewsResponseGetToOneRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiCustomerReviewsResponseGetToOneRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsCustomerReviews** | **[]string** | the fields to include for returned resources of type customerReviews | 
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

