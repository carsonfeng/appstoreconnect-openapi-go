# \AppInfosApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**AppInfosAgeRatingDeclarationGetToOneRelated**](AppInfosApi.md#AppInfosAgeRatingDeclarationGetToOneRelated) | **Get** /v1/appInfos/{id}/ageRatingDeclaration | 
[**AppInfosAppInfoLocalizationsGetToManyRelated**](AppInfosApi.md#AppInfosAppInfoLocalizationsGetToManyRelated) | **Get** /v1/appInfos/{id}/appInfoLocalizations | 
[**AppInfosGetInstance**](AppInfosApi.md#AppInfosGetInstance) | **Get** /v1/appInfos/{id} | 
[**AppInfosPrimaryCategoryGetToOneRelated**](AppInfosApi.md#AppInfosPrimaryCategoryGetToOneRelated) | **Get** /v1/appInfos/{id}/primaryCategory | 
[**AppInfosPrimarySubcategoryOneGetToOneRelated**](AppInfosApi.md#AppInfosPrimarySubcategoryOneGetToOneRelated) | **Get** /v1/appInfos/{id}/primarySubcategoryOne | 
[**AppInfosPrimarySubcategoryTwoGetToOneRelated**](AppInfosApi.md#AppInfosPrimarySubcategoryTwoGetToOneRelated) | **Get** /v1/appInfos/{id}/primarySubcategoryTwo | 
[**AppInfosSecondaryCategoryGetToOneRelated**](AppInfosApi.md#AppInfosSecondaryCategoryGetToOneRelated) | **Get** /v1/appInfos/{id}/secondaryCategory | 
[**AppInfosSecondarySubcategoryOneGetToOneRelated**](AppInfosApi.md#AppInfosSecondarySubcategoryOneGetToOneRelated) | **Get** /v1/appInfos/{id}/secondarySubcategoryOne | 
[**AppInfosSecondarySubcategoryTwoGetToOneRelated**](AppInfosApi.md#AppInfosSecondarySubcategoryTwoGetToOneRelated) | **Get** /v1/appInfos/{id}/secondarySubcategoryTwo | 
[**AppInfosUpdateInstance**](AppInfosApi.md#AppInfosUpdateInstance) | **Patch** /v1/appInfos/{id} | 



## AppInfosAgeRatingDeclarationGetToOneRelated

> AgeRatingDeclarationResponse AppInfosAgeRatingDeclarationGetToOneRelated(ctx, id).FieldsAgeRatingDeclarations(fieldsAgeRatingDeclarations).Execute()



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
    fieldsAgeRatingDeclarations := []string{"FieldsAgeRatingDeclarations_example"} // []string | the fields to include for returned resources of type ageRatingDeclarations (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppInfosApi.AppInfosAgeRatingDeclarationGetToOneRelated(context.Background(), id).FieldsAgeRatingDeclarations(fieldsAgeRatingDeclarations).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppInfosApi.AppInfosAgeRatingDeclarationGetToOneRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppInfosAgeRatingDeclarationGetToOneRelated`: AgeRatingDeclarationResponse
    fmt.Fprintf(os.Stdout, "Response from `AppInfosApi.AppInfosAgeRatingDeclarationGetToOneRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppInfosAgeRatingDeclarationGetToOneRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsAgeRatingDeclarations** | **[]string** | the fields to include for returned resources of type ageRatingDeclarations | 

### Return type

[**AgeRatingDeclarationResponse**](AgeRatingDeclarationResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppInfosAppInfoLocalizationsGetToManyRelated

> AppInfoLocalizationsResponse AppInfosAppInfoLocalizationsGetToManyRelated(ctx, id).FilterLocale(filterLocale).FieldsAppInfos(fieldsAppInfos).FieldsAppInfoLocalizations(fieldsAppInfoLocalizations).Limit(limit).Include(include).Execute()



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
    filterLocale := []string{"Inner_example"} // []string | filter by attribute 'locale' (optional)
    fieldsAppInfos := []string{"FieldsAppInfos_example"} // []string | the fields to include for returned resources of type appInfos (optional)
    fieldsAppInfoLocalizations := []string{"FieldsAppInfoLocalizations_example"} // []string | the fields to include for returned resources of type appInfoLocalizations (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppInfosApi.AppInfosAppInfoLocalizationsGetToManyRelated(context.Background(), id).FilterLocale(filterLocale).FieldsAppInfos(fieldsAppInfos).FieldsAppInfoLocalizations(fieldsAppInfoLocalizations).Limit(limit).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppInfosApi.AppInfosAppInfoLocalizationsGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppInfosAppInfoLocalizationsGetToManyRelated`: AppInfoLocalizationsResponse
    fmt.Fprintf(os.Stdout, "Response from `AppInfosApi.AppInfosAppInfoLocalizationsGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppInfosAppInfoLocalizationsGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **filterLocale** | **[]string** | filter by attribute &#39;locale&#39; | 
 **fieldsAppInfos** | **[]string** | the fields to include for returned resources of type appInfos | 
 **fieldsAppInfoLocalizations** | **[]string** | the fields to include for returned resources of type appInfoLocalizations | 
 **limit** | **int32** | maximum resources per page | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**AppInfoLocalizationsResponse**](AppInfoLocalizationsResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppInfosGetInstance

> AppInfoResponse AppInfosGetInstance(ctx, id).FieldsAppInfos(fieldsAppInfos).Include(include).FieldsAgeRatingDeclarations(fieldsAgeRatingDeclarations).FieldsAppInfoLocalizations(fieldsAppInfoLocalizations).FieldsAppCategories(fieldsAppCategories).LimitAppInfoLocalizations(limitAppInfoLocalizations).Execute()



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
    fieldsAppInfos := []string{"FieldsAppInfos_example"} // []string | the fields to include for returned resources of type appInfos (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)
    fieldsAgeRatingDeclarations := []string{"FieldsAgeRatingDeclarations_example"} // []string | the fields to include for returned resources of type ageRatingDeclarations (optional)
    fieldsAppInfoLocalizations := []string{"FieldsAppInfoLocalizations_example"} // []string | the fields to include for returned resources of type appInfoLocalizations (optional)
    fieldsAppCategories := []string{"FieldsAppCategories_example"} // []string | the fields to include for returned resources of type appCategories (optional)
    limitAppInfoLocalizations := int32(56) // int32 | maximum number of related appInfoLocalizations returned (when they are included) (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppInfosApi.AppInfosGetInstance(context.Background(), id).FieldsAppInfos(fieldsAppInfos).Include(include).FieldsAgeRatingDeclarations(fieldsAgeRatingDeclarations).FieldsAppInfoLocalizations(fieldsAppInfoLocalizations).FieldsAppCategories(fieldsAppCategories).LimitAppInfoLocalizations(limitAppInfoLocalizations).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppInfosApi.AppInfosGetInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppInfosGetInstance`: AppInfoResponse
    fmt.Fprintf(os.Stdout, "Response from `AppInfosApi.AppInfosGetInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppInfosGetInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsAppInfos** | **[]string** | the fields to include for returned resources of type appInfos | 
 **include** | **[]string** | comma-separated list of relationships to include | 
 **fieldsAgeRatingDeclarations** | **[]string** | the fields to include for returned resources of type ageRatingDeclarations | 
 **fieldsAppInfoLocalizations** | **[]string** | the fields to include for returned resources of type appInfoLocalizations | 
 **fieldsAppCategories** | **[]string** | the fields to include for returned resources of type appCategories | 
 **limitAppInfoLocalizations** | **int32** | maximum number of related appInfoLocalizations returned (when they are included) | 

### Return type

[**AppInfoResponse**](AppInfoResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppInfosPrimaryCategoryGetToOneRelated

> AppCategoryResponse AppInfosPrimaryCategoryGetToOneRelated(ctx, id).FieldsAppCategories(fieldsAppCategories).LimitSubcategories(limitSubcategories).Include(include).Execute()



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
    fieldsAppCategories := []string{"FieldsAppCategories_example"} // []string | the fields to include for returned resources of type appCategories (optional)
    limitSubcategories := int32(56) // int32 | maximum number of related subcategories returned (when they are included) (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppInfosApi.AppInfosPrimaryCategoryGetToOneRelated(context.Background(), id).FieldsAppCategories(fieldsAppCategories).LimitSubcategories(limitSubcategories).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppInfosApi.AppInfosPrimaryCategoryGetToOneRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppInfosPrimaryCategoryGetToOneRelated`: AppCategoryResponse
    fmt.Fprintf(os.Stdout, "Response from `AppInfosApi.AppInfosPrimaryCategoryGetToOneRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppInfosPrimaryCategoryGetToOneRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsAppCategories** | **[]string** | the fields to include for returned resources of type appCategories | 
 **limitSubcategories** | **int32** | maximum number of related subcategories returned (when they are included) | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**AppCategoryResponse**](AppCategoryResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppInfosPrimarySubcategoryOneGetToOneRelated

> AppCategoryResponse AppInfosPrimarySubcategoryOneGetToOneRelated(ctx, id).FieldsAppCategories(fieldsAppCategories).LimitSubcategories(limitSubcategories).Include(include).Execute()



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
    fieldsAppCategories := []string{"FieldsAppCategories_example"} // []string | the fields to include for returned resources of type appCategories (optional)
    limitSubcategories := int32(56) // int32 | maximum number of related subcategories returned (when they are included) (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppInfosApi.AppInfosPrimarySubcategoryOneGetToOneRelated(context.Background(), id).FieldsAppCategories(fieldsAppCategories).LimitSubcategories(limitSubcategories).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppInfosApi.AppInfosPrimarySubcategoryOneGetToOneRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppInfosPrimarySubcategoryOneGetToOneRelated`: AppCategoryResponse
    fmt.Fprintf(os.Stdout, "Response from `AppInfosApi.AppInfosPrimarySubcategoryOneGetToOneRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppInfosPrimarySubcategoryOneGetToOneRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsAppCategories** | **[]string** | the fields to include for returned resources of type appCategories | 
 **limitSubcategories** | **int32** | maximum number of related subcategories returned (when they are included) | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**AppCategoryResponse**](AppCategoryResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppInfosPrimarySubcategoryTwoGetToOneRelated

> AppCategoryResponse AppInfosPrimarySubcategoryTwoGetToOneRelated(ctx, id).FieldsAppCategories(fieldsAppCategories).LimitSubcategories(limitSubcategories).Include(include).Execute()



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
    fieldsAppCategories := []string{"FieldsAppCategories_example"} // []string | the fields to include for returned resources of type appCategories (optional)
    limitSubcategories := int32(56) // int32 | maximum number of related subcategories returned (when they are included) (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppInfosApi.AppInfosPrimarySubcategoryTwoGetToOneRelated(context.Background(), id).FieldsAppCategories(fieldsAppCategories).LimitSubcategories(limitSubcategories).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppInfosApi.AppInfosPrimarySubcategoryTwoGetToOneRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppInfosPrimarySubcategoryTwoGetToOneRelated`: AppCategoryResponse
    fmt.Fprintf(os.Stdout, "Response from `AppInfosApi.AppInfosPrimarySubcategoryTwoGetToOneRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppInfosPrimarySubcategoryTwoGetToOneRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsAppCategories** | **[]string** | the fields to include for returned resources of type appCategories | 
 **limitSubcategories** | **int32** | maximum number of related subcategories returned (when they are included) | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**AppCategoryResponse**](AppCategoryResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppInfosSecondaryCategoryGetToOneRelated

> AppCategoryResponse AppInfosSecondaryCategoryGetToOneRelated(ctx, id).FieldsAppCategories(fieldsAppCategories).LimitSubcategories(limitSubcategories).Include(include).Execute()



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
    fieldsAppCategories := []string{"FieldsAppCategories_example"} // []string | the fields to include for returned resources of type appCategories (optional)
    limitSubcategories := int32(56) // int32 | maximum number of related subcategories returned (when they are included) (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppInfosApi.AppInfosSecondaryCategoryGetToOneRelated(context.Background(), id).FieldsAppCategories(fieldsAppCategories).LimitSubcategories(limitSubcategories).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppInfosApi.AppInfosSecondaryCategoryGetToOneRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppInfosSecondaryCategoryGetToOneRelated`: AppCategoryResponse
    fmt.Fprintf(os.Stdout, "Response from `AppInfosApi.AppInfosSecondaryCategoryGetToOneRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppInfosSecondaryCategoryGetToOneRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsAppCategories** | **[]string** | the fields to include for returned resources of type appCategories | 
 **limitSubcategories** | **int32** | maximum number of related subcategories returned (when they are included) | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**AppCategoryResponse**](AppCategoryResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppInfosSecondarySubcategoryOneGetToOneRelated

> AppCategoryResponse AppInfosSecondarySubcategoryOneGetToOneRelated(ctx, id).FieldsAppCategories(fieldsAppCategories).LimitSubcategories(limitSubcategories).Include(include).Execute()



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
    fieldsAppCategories := []string{"FieldsAppCategories_example"} // []string | the fields to include for returned resources of type appCategories (optional)
    limitSubcategories := int32(56) // int32 | maximum number of related subcategories returned (when they are included) (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppInfosApi.AppInfosSecondarySubcategoryOneGetToOneRelated(context.Background(), id).FieldsAppCategories(fieldsAppCategories).LimitSubcategories(limitSubcategories).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppInfosApi.AppInfosSecondarySubcategoryOneGetToOneRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppInfosSecondarySubcategoryOneGetToOneRelated`: AppCategoryResponse
    fmt.Fprintf(os.Stdout, "Response from `AppInfosApi.AppInfosSecondarySubcategoryOneGetToOneRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppInfosSecondarySubcategoryOneGetToOneRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsAppCategories** | **[]string** | the fields to include for returned resources of type appCategories | 
 **limitSubcategories** | **int32** | maximum number of related subcategories returned (when they are included) | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**AppCategoryResponse**](AppCategoryResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppInfosSecondarySubcategoryTwoGetToOneRelated

> AppCategoryResponse AppInfosSecondarySubcategoryTwoGetToOneRelated(ctx, id).FieldsAppCategories(fieldsAppCategories).LimitSubcategories(limitSubcategories).Include(include).Execute()



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
    fieldsAppCategories := []string{"FieldsAppCategories_example"} // []string | the fields to include for returned resources of type appCategories (optional)
    limitSubcategories := int32(56) // int32 | maximum number of related subcategories returned (when they are included) (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppInfosApi.AppInfosSecondarySubcategoryTwoGetToOneRelated(context.Background(), id).FieldsAppCategories(fieldsAppCategories).LimitSubcategories(limitSubcategories).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppInfosApi.AppInfosSecondarySubcategoryTwoGetToOneRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppInfosSecondarySubcategoryTwoGetToOneRelated`: AppCategoryResponse
    fmt.Fprintf(os.Stdout, "Response from `AppInfosApi.AppInfosSecondarySubcategoryTwoGetToOneRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppInfosSecondarySubcategoryTwoGetToOneRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsAppCategories** | **[]string** | the fields to include for returned resources of type appCategories | 
 **limitSubcategories** | **int32** | maximum number of related subcategories returned (when they are included) | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**AppCategoryResponse**](AppCategoryResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## AppInfosUpdateInstance

> AppInfoResponse AppInfosUpdateInstance(ctx, id).AppInfoUpdateRequest(appInfoUpdateRequest).Execute()



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
    appInfoUpdateRequest := *openapiclient.NewAppInfoUpdateRequest(*openapiclient.NewAppInfoUpdateRequestData("Type_example", "Id_example")) // AppInfoUpdateRequest | AppInfo representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.AppInfosApi.AppInfosUpdateInstance(context.Background(), id).AppInfoUpdateRequest(appInfoUpdateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `AppInfosApi.AppInfosUpdateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `AppInfosUpdateInstance`: AppInfoResponse
    fmt.Fprintf(os.Stdout, "Response from `AppInfosApi.AppInfosUpdateInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiAppInfosUpdateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **appInfoUpdateRequest** | [**AppInfoUpdateRequest**](AppInfoUpdateRequest.md) | AppInfo representation | 

### Return type

[**AppInfoResponse**](AppInfoResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

