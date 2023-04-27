# \CiBuildActionsApi

All URIs are relative to *https://api.appstoreconnect.apple.com*

Method | HTTP request | Description
------------- | ------------- | -------------
[**CiBuildActionsArtifactsGetToManyRelated**](CiBuildActionsApi.md#CiBuildActionsArtifactsGetToManyRelated) | **Get** /v1/ciBuildActions/{id}/artifacts | 
[**CiBuildActionsBuildRunGetToOneRelated**](CiBuildActionsApi.md#CiBuildActionsBuildRunGetToOneRelated) | **Get** /v1/ciBuildActions/{id}/buildRun | 
[**CiBuildActionsGetInstance**](CiBuildActionsApi.md#CiBuildActionsGetInstance) | **Get** /v1/ciBuildActions/{id} | 
[**CiBuildActionsIssuesGetToManyRelated**](CiBuildActionsApi.md#CiBuildActionsIssuesGetToManyRelated) | **Get** /v1/ciBuildActions/{id}/issues | 
[**CiBuildActionsTestResultsGetToManyRelated**](CiBuildActionsApi.md#CiBuildActionsTestResultsGetToManyRelated) | **Get** /v1/ciBuildActions/{id}/testResults | 



## CiBuildActionsArtifactsGetToManyRelated

> CiArtifactsResponse CiBuildActionsArtifactsGetToManyRelated(ctx, id).FieldsCiArtifacts(fieldsCiArtifacts).Limit(limit).Execute()



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
    fieldsCiArtifacts := []string{"FieldsCiArtifacts_example"} // []string | the fields to include for returned resources of type ciArtifacts (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.CiBuildActionsApi.CiBuildActionsArtifactsGetToManyRelated(context.Background(), id).FieldsCiArtifacts(fieldsCiArtifacts).Limit(limit).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `CiBuildActionsApi.CiBuildActionsArtifactsGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `CiBuildActionsArtifactsGetToManyRelated`: CiArtifactsResponse
    fmt.Fprintf(os.Stdout, "Response from `CiBuildActionsApi.CiBuildActionsArtifactsGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiCiBuildActionsArtifactsGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsCiArtifacts** | **[]string** | the fields to include for returned resources of type ciArtifacts | 
 **limit** | **int32** | maximum resources per page | 

### Return type

[**CiArtifactsResponse**](CiArtifactsResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## CiBuildActionsBuildRunGetToOneRelated

> CiBuildRunResponse CiBuildActionsBuildRunGetToOneRelated(ctx, id).FieldsScmGitReferences(fieldsScmGitReferences).FieldsCiBuildRuns(fieldsCiBuildRuns).FieldsCiWorkflows(fieldsCiWorkflows).FieldsScmPullRequests(fieldsScmPullRequests).FieldsCiProducts(fieldsCiProducts).FieldsBuilds(fieldsBuilds).LimitBuilds(limitBuilds).Include(include).Execute()



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
    fieldsCiBuildRuns := []string{"FieldsCiBuildRuns_example"} // []string | the fields to include for returned resources of type ciBuildRuns (optional)
    fieldsCiWorkflows := []string{"FieldsCiWorkflows_example"} // []string | the fields to include for returned resources of type ciWorkflows (optional)
    fieldsScmPullRequests := []string{"FieldsScmPullRequests_example"} // []string | the fields to include for returned resources of type scmPullRequests (optional)
    fieldsCiProducts := []string{"FieldsCiProducts_example"} // []string | the fields to include for returned resources of type ciProducts (optional)
    fieldsBuilds := []string{"FieldsBuilds_example"} // []string | the fields to include for returned resources of type builds (optional)
    limitBuilds := int32(56) // int32 | maximum number of related builds returned (when they are included) (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.CiBuildActionsApi.CiBuildActionsBuildRunGetToOneRelated(context.Background(), id).FieldsScmGitReferences(fieldsScmGitReferences).FieldsCiBuildRuns(fieldsCiBuildRuns).FieldsCiWorkflows(fieldsCiWorkflows).FieldsScmPullRequests(fieldsScmPullRequests).FieldsCiProducts(fieldsCiProducts).FieldsBuilds(fieldsBuilds).LimitBuilds(limitBuilds).Include(include).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `CiBuildActionsApi.CiBuildActionsBuildRunGetToOneRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `CiBuildActionsBuildRunGetToOneRelated`: CiBuildRunResponse
    fmt.Fprintf(os.Stdout, "Response from `CiBuildActionsApi.CiBuildActionsBuildRunGetToOneRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiCiBuildActionsBuildRunGetToOneRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsScmGitReferences** | **[]string** | the fields to include for returned resources of type scmGitReferences | 
 **fieldsCiBuildRuns** | **[]string** | the fields to include for returned resources of type ciBuildRuns | 
 **fieldsCiWorkflows** | **[]string** | the fields to include for returned resources of type ciWorkflows | 
 **fieldsScmPullRequests** | **[]string** | the fields to include for returned resources of type scmPullRequests | 
 **fieldsCiProducts** | **[]string** | the fields to include for returned resources of type ciProducts | 
 **fieldsBuilds** | **[]string** | the fields to include for returned resources of type builds | 
 **limitBuilds** | **int32** | maximum number of related builds returned (when they are included) | 
 **include** | **[]string** | comma-separated list of relationships to include | 

### Return type

[**CiBuildRunResponse**](CiBuildRunResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## CiBuildActionsGetInstance

> CiBuildActionResponse CiBuildActionsGetInstance(ctx, id).FieldsCiBuildActions(fieldsCiBuildActions).Include(include).FieldsCiIssues(fieldsCiIssues).FieldsCiBuildRuns(fieldsCiBuildRuns).FieldsCiTestResults(fieldsCiTestResults).FieldsCiArtifacts(fieldsCiArtifacts).Execute()



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
    fieldsCiBuildActions := []string{"FieldsCiBuildActions_example"} // []string | the fields to include for returned resources of type ciBuildActions (optional)
    include := []string{"Include_example"} // []string | comma-separated list of relationships to include (optional)
    fieldsCiIssues := []string{"FieldsCiIssues_example"} // []string | the fields to include for returned resources of type ciIssues (optional)
    fieldsCiBuildRuns := []string{"FieldsCiBuildRuns_example"} // []string | the fields to include for returned resources of type ciBuildRuns (optional)
    fieldsCiTestResults := []string{"FieldsCiTestResults_example"} // []string | the fields to include for returned resources of type ciTestResults (optional)
    fieldsCiArtifacts := []string{"FieldsCiArtifacts_example"} // []string | the fields to include for returned resources of type ciArtifacts (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.CiBuildActionsApi.CiBuildActionsGetInstance(context.Background(), id).FieldsCiBuildActions(fieldsCiBuildActions).Include(include).FieldsCiIssues(fieldsCiIssues).FieldsCiBuildRuns(fieldsCiBuildRuns).FieldsCiTestResults(fieldsCiTestResults).FieldsCiArtifacts(fieldsCiArtifacts).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `CiBuildActionsApi.CiBuildActionsGetInstance``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `CiBuildActionsGetInstance`: CiBuildActionResponse
    fmt.Fprintf(os.Stdout, "Response from `CiBuildActionsApi.CiBuildActionsGetInstance`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiCiBuildActionsGetInstanceRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsCiBuildActions** | **[]string** | the fields to include for returned resources of type ciBuildActions | 
 **include** | **[]string** | comma-separated list of relationships to include | 
 **fieldsCiIssues** | **[]string** | the fields to include for returned resources of type ciIssues | 
 **fieldsCiBuildRuns** | **[]string** | the fields to include for returned resources of type ciBuildRuns | 
 **fieldsCiTestResults** | **[]string** | the fields to include for returned resources of type ciTestResults | 
 **fieldsCiArtifacts** | **[]string** | the fields to include for returned resources of type ciArtifacts | 

### Return type

[**CiBuildActionResponse**](CiBuildActionResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## CiBuildActionsIssuesGetToManyRelated

> CiIssuesResponse CiBuildActionsIssuesGetToManyRelated(ctx, id).FieldsCiIssues(fieldsCiIssues).Limit(limit).Execute()



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
    fieldsCiIssues := []string{"FieldsCiIssues_example"} // []string | the fields to include for returned resources of type ciIssues (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.CiBuildActionsApi.CiBuildActionsIssuesGetToManyRelated(context.Background(), id).FieldsCiIssues(fieldsCiIssues).Limit(limit).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `CiBuildActionsApi.CiBuildActionsIssuesGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `CiBuildActionsIssuesGetToManyRelated`: CiIssuesResponse
    fmt.Fprintf(os.Stdout, "Response from `CiBuildActionsApi.CiBuildActionsIssuesGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiCiBuildActionsIssuesGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsCiIssues** | **[]string** | the fields to include for returned resources of type ciIssues | 
 **limit** | **int32** | maximum resources per page | 

### Return type

[**CiIssuesResponse**](CiIssuesResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)


## CiBuildActionsTestResultsGetToManyRelated

> CiTestResultsResponse CiBuildActionsTestResultsGetToManyRelated(ctx, id).FieldsCiTestResults(fieldsCiTestResults).Limit(limit).Execute()



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
    fieldsCiTestResults := []string{"FieldsCiTestResults_example"} // []string | the fields to include for returned resources of type ciTestResults (optional)
    limit := int32(56) // int32 | maximum resources per page (optional)

    configuration := openapiclient.NewConfiguration()
    apiClient := openapiclient.NewAPIClient(configuration)
    resp, r, err := apiClient.CiBuildActionsApi.CiBuildActionsTestResultsGetToManyRelated(context.Background(), id).FieldsCiTestResults(fieldsCiTestResults).Limit(limit).Execute()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error when calling `CiBuildActionsApi.CiBuildActionsTestResultsGetToManyRelated``: %v\n", err)
        fmt.Fprintf(os.Stderr, "Full HTTP response: %v\n", r)
    }
    // response from `CiBuildActionsTestResultsGetToManyRelated`: CiTestResultsResponse
    fmt.Fprintf(os.Stdout, "Response from `CiBuildActionsApi.CiBuildActionsTestResultsGetToManyRelated`: %v\n", resp)
}
```

### Path Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
**ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
**id** | **string** | the id of the requested resource | 

### Other Parameters

Other parameters are passed through a pointer to a apiCiBuildActionsTestResultsGetToManyRelatedRequest struct via the builder pattern


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------

 **fieldsCiTestResults** | **[]string** | the fields to include for returned resources of type ciTestResults | 
 **limit** | **int32** | maximum resources per page | 

### Return type

[**CiTestResultsResponse**](CiTestResultsResponse.md)

### Authorization

[itc-bearer-token](../README.md#itc-bearer-token)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints)
[[Back to Model list]](../README.md#documentation-for-models)
[[Back to README]](../README.md)

