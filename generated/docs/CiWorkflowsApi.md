# \CiWorkflowsApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**CiWorkflowsBuildRunsGetToManyRelated**](CiWorkflowsApi.md#CiWorkflowsBuildRunsGetToManyRelated) | **Get** /v1/ciWorkflows/{id}/buildRuns | 
[**CiWorkflowsCreateInstance**](CiWorkflowsApi.md#CiWorkflowsCreateInstance) | **Post** /v1/ciWorkflows | 
[**CiWorkflowsDeleteInstance**](CiWorkflowsApi.md#CiWorkflowsDeleteInstance) | **Delete** /v1/ciWorkflows/{id} | 
[**CiWorkflowsGetInstance**](CiWorkflowsApi.md#CiWorkflowsGetInstance) | **Get** /v1/ciWorkflows/{id} | 
[**CiWorkflowsRepositoryGetToOneRelated**](CiWorkflowsApi.md#CiWorkflowsRepositoryGetToOneRelated) | **Get** /v1/ciWorkflows/{id}/repository | 
[**CiWorkflowsUpdateInstance**](CiWorkflowsApi.md#CiWorkflowsUpdateInstance) | **Patch** /v1/ciWorkflows/{id} | 



## CiWorkflowsBuildRunsGetToManyRelated

> CiBuildRunsResponse CiWorkflowsBuildRunsGetToManyRelated(ctx, id).FilterBuilds(filterBuilds).FieldsScmGitReferences(fieldsScmGitReferences).FieldsCiBuildRuns(fieldsCiBuildRuns).FieldsCiWorkflows(fieldsCiWorkflows).FieldsScmPullRequests(fieldsScmPullRequests).FieldsCiProducts(fieldsCiProducts).FieldsBuilds(fieldsBuilds).Limit(limit).LimitBuilds(limitBuilds).Include(include).Execute()



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
    filterBuilds := []string{"Inner_example"} // []string | filter by id(s) of related 'builds' (optional)
    fieldsScmGitReferences := []string{"FieldsScmGitReferences_example"} // []string | the fields to include for returned resources of type scmGitReferences (optional)
    fieldsCiBuildRuns := []string{"FieldsCiBuildRuns_example"} // []string | the fields to include for returned resources of type ciBuildRuns (optional)
    fieldsCiWorkflows := []string{"FieldsCiWorkflows_example"} // []string | the fields to include for returned resources of type ciWorkflows (optional)
    fieldsScmPullRequests := []string{"FieldsScmPullRequests_example"} // []string | the fields to include for returned resources of type scmPullRequests (optional)
    fieldsCiProducts := []string{"FieldsCiProducts_example"} // []string | the fields to include for returned resources of type ciProducts (optional)
    fieldsBuilds := []string{"FieldsBuilds_example"} // []string | the fields to include for returned resources of type builds (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)
    limitBuilds := int32(56) // int32 | maximum number of related builds returned (when they are included) (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.CiWorkflowsApi.CiWorkflowsBuildRunsGetToManyRelated(context.Background(), id).FilterBuilds(filterBuilds).FieldsScmGitReferences(fieldsScmGitReferences).FieldsCiBuildRuns(fieldsCiBuildRuns).FieldsCiWorkflows(fieldsCiWorkflows).FieldsScmPullRequests(fieldsScmPullRequests).FieldsCiProducts(fieldsCiProducts).FieldsBuilds(fieldsBuilds).Limit(limit).LimitBuilds(limitBuilds).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `CiWorkflowsApi.CiWorkflowsBuildRunsGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `CiWorkflowsBuildRunsGetToManyRelated`: CiBuildRunsResponse
    fmt.Fprintf(os.Stdout, "Response from `CiWorkflowsApi.CiWorkflowsBuildRunsGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiCiWorkflowsBuildRunsGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **filterBuilds** | **[]string** | filter by id(s) of related &#39;builds&#39; | 
 **fieldsScmGitReferences** | **[]string** | the fields to include for returned resources of type scmGitReferences | 
 **fieldsCiBuildRuns** | **[]string** | the fields to include for returned resources of type ciBuildRuns | 
 **fieldsCiWorkflows** | **[]string** | the fields to include for returned resources of type ciWorkflows | 
 **fieldsScmPullRequests** | **[]string** | the fields to include for returned resources of type scmPullRequests | 
 **fieldsCiProducts** | **[]string** | the fields to include for returned resources of type ciProducts | 
 **fieldsBuilds** | **[]string** | the fields to include for returned resources of type builds | 
 **limit** | **int32** | maximum resources per page | 
 **limitBuilds** | **int32** | maximum number of related builds returned (when they are included) | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**CiBuildRunsResponse**](CiBuildRunsResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## CiWorkflowsCreateInstance

> CiWorkflowResponse CiWorkflowsCreateInstance(ctx).CiWorkflowCreateRequest(ciWorkflowCreateRequest).Execute()



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
    ciWorkflowCreateRequest := *openapiclient.NewCiWorkflowCreateRequest(*openapiclient.NewCiWorkflowCreateRequestData("Type_example", *openapiclient.NewCiWorkflowCreateRequestDataAttributes("Name_example", "Description_example", []openapiclient.CiAction{*openapiclient.NewCiAction()}, false, false, "ContainerFilePath_example"), *openapiclient.NewCiWorkflowCreateRequestDataRelationships(*openapiclient.NewCiWorkflowCreateRequestDataRelationshipsProduct(*openapiclient.NewAppRelationshipsCiProductData("Type_example", "Id_example")), *openapiclient.NewCiWorkflowCreateRequestDataRelationshipsRepository(*openapiclient.NewCiProductRelationshipsPrimaryRepositoriesDataInner("Type_example", "Id_example")), *openapiclient.NewCiWorkflowCreateRequestDataRelationshipsXcodeVersion(*openapiclient.NewCiMacOsVersionRelationshipsXcodeVersionsDataInner("Type_example", "Id_example")), *openapiclient.NewCiWorkflowCreateRequestDataRelationshipsMacOsVersion(*openapiclient.NewCiWorkflowRelationshipsMacOsVersionData("Type_example", "Id_example"))))) // CiWorkflowCreateRequest | CiWorkflow representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.CiWorkflowsApi.CiWorkflowsCreateInstance(context.Background()).CiWorkflowCreateRequest(ciWorkflowCreateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `CiWorkflowsApi.CiWorkflowsCreateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `CiWorkflowsCreateInstance`: CiWorkflowResponse
    fmt.Fprintf(os.Stdout, "Response from `CiWorkflowsApi.CiWorkflowsCreateInstance`: %v\n", resp)
}
```

### Path Parameters



### Other Parameters

Other parameters are passed through a pointer to a apiCiWorkflowsCreateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ciWorkflowCreateRequest** | [**CiWorkflowCreateRequest**](CiWorkflowCreateRequest.md) | CiWorkflow representation | 

### Return type

[**CiWorkflowResponse**](CiWorkflowResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## CiWorkflowsDeleteInstance

> CiWorkflowsDeleteInstance(ctx, id).Execute()



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
    r, err := apiClient.CiWorkflowsApi.CiWorkflowsDeleteInstance(context.Background(), id).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `CiWorkflowsApi.CiWorkflowsDeleteInstance``: %v\n", err)
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

Other parameters are passed through a pointer to a apiCiWorkflowsDeleteInstanceRequest struct via the builder pattern


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


## CiWorkflowsGetInstance

> CiWorkflowResponse CiWorkflowsGetInstance(ctx, id).FieldsCiWorkflows(fieldsCiWorkflows).Include(include).FieldsCiBuildRuns(fieldsCiBuildRuns).FieldsScmRepositories(fieldsScmRepositories).Execute()



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
    fieldsCiWorkflows := []string{"FieldsCiWorkflows_example"} // []string | the fields to include for returned resources of type ciWorkflows (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)
    fieldsCiBuildRuns := []string{"FieldsCiBuildRuns_example"} // []string | the fields to include for returned resources of type ciBuildRuns (optional)
    fieldsScmRepositories := []string{"FieldsScmRepositories_example"} // []string | the fields to include for returned resources of type scmRepositories (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.CiWorkflowsApi.CiWorkflowsGetInstance(context.Background(), id).FieldsCiWorkflows(fieldsCiWorkflows).Include(include).FieldsCiBuildRuns(fieldsCiBuildRuns).FieldsScmRepositories(fieldsScmRepositories).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `CiWorkflowsApi.CiWorkflowsGetInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `CiWorkflowsGetInstance`: CiWorkflowResponse
    fmt.Fprintf(os.Stdout, "Response from `CiWorkflowsApi.CiWorkflowsGetInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiCiWorkflowsGetInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsCiWorkflows** | **[]string** | the fields to include for returned resources of type ciWorkflows | 
 **include** | **[]string** | comma-separated list of relationships to include | 
 **fieldsCiBuildRuns** | **[]string** | the fields to include for returned resources of type ciBuildRuns | 
 **fieldsScmRepositories** | **[]string** | the fields to include for returned resources of type scmRepositories | 

### Return type

[**CiWorkflowResponse**](CiWorkflowResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## CiWorkflowsRepositoryGetToOneRelated

> ScmRepositoryResponse CiWorkflowsRepositoryGetToOneRelated(ctx, id).FieldsScmGitReferences(fieldsScmGitReferences).FieldsScmProviders(fieldsScmProviders).FieldsScmRepositories(fieldsScmRepositories).Include(include).Execute()



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
    fieldsScmGitReferences := []string{"FieldsScmGitReferences_example"} // []string | the fields to include for returned resources of type scmGitReferences (optional)
    fieldsScmProviders := []string{"FieldsScmProviders_example"} // []string | the fields to include for returned resources of type scmProviders (optional)
    fieldsScmRepositories := []string{"FieldsScmRepositories_example"} // []string | the fields to include for returned resources of type scmRepositories (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.CiWorkflowsApi.CiWorkflowsRepositoryGetToOneRelated(context.Background(), id).FieldsScmGitReferences(fieldsScmGitReferences).FieldsScmProviders(fieldsScmProviders).FieldsScmRepositories(fieldsScmRepositories).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `CiWorkflowsApi.CiWorkflowsRepositoryGetToOneRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `CiWorkflowsRepositoryGetToOneRelated`: ScmRepositoryResponse
    fmt.Fprintf(os.Stdout, "Response from `CiWorkflowsApi.CiWorkflowsRepositoryGetToOneRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiCiWorkflowsRepositoryGetToOneRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsScmGitReferences** | **[]string** | the fields to include for returned resources of type scmGitReferences | 
 **fieldsScmProviders** | **[]string** | the fields to include for returned resources of type scmProviders | 
 **fieldsScmRepositories** | **[]string** | the fields to include for returned resources of type scmRepositories | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**ScmRepositoryResponse**](ScmRepositoryResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## CiWorkflowsUpdateInstance

> CiWorkflowResponse CiWorkflowsUpdateInstance(ctx, id).CiWorkflowUpdateRequest(ciWorkflowUpdateRequest).Execute()



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
    ciWorkflowUpdateRequest := *openapiclient.NewCiWorkflowUpdateRequest(*openapiclient.NewCiWorkflowUpdateRequestData("Type_example", "Id_example")) // CiWorkflowUpdateRequest | CiWorkflow representation

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.CiWorkflowsApi.CiWorkflowsUpdateInstance(context.Background(), id).CiWorkflowUpdateRequest(ciWorkflowUpdateRequest).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `CiWorkflowsApi.CiWorkflowsUpdateInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `CiWorkflowsUpdateInstance`: CiWorkflowResponse
    fmt.Fprintf(os.Stdout, "Response from `CiWorkflowsApi.CiWorkflowsUpdateInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiCiWorkflowsUpdateInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **ciWorkflowUpdateRequest** | [**CiWorkflowUpdateRequest**](CiWorkflowUpdateRequest.md) | CiWorkflow representation | 

### Return type

[**CiWorkflowResponse**](CiWorkflowResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

