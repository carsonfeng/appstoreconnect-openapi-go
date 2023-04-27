/*
App Store Connect API

No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)

API version: 2.3
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package openapi

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// ScmRepositoriesApiService ScmRepositoriesApi service
type ScmRepositoriesApiService service

type ApiScmRepositoriesGetCollectionRequest struct {
	ctx                    context.Context
	ApiService             *ScmRepositoriesApiService
	filterId               *[]string
	fieldsScmRepositories  *[]string
	limit                  *int32
	include                *[]string
	fieldsScmGitReferences *[]string
	fieldsScmPullRequests  *[]string
}

// filter by id(s)
func (r ApiScmRepositoriesGetCollectionRequest) FilterId(filterId []string) ApiScmRepositoriesGetCollectionRequest {
	r.filterId = &filterId
	return r
}

// the fields to include for returned resources of type scmRepositories
func (r ApiScmRepositoriesGetCollectionRequest) FieldsScmRepositories(fieldsScmRepositories []string) ApiScmRepositoriesGetCollectionRequest {
	r.fieldsScmRepositories = &fieldsScmRepositories
	return r
}

// maximum resources per page
func (r ApiScmRepositoriesGetCollectionRequest) Limit(limit int32) ApiScmRepositoriesGetCollectionRequest {
	r.limit = &limit
	return r
}

// comma-separated list of relationships to include
func (r ApiScmRepositoriesGetCollectionRequest) Include(include []string) ApiScmRepositoriesGetCollectionRequest {
	r.include = &include
	return r
}

// the fields to include for returned resources of type scmGitReferences
func (r ApiScmRepositoriesGetCollectionRequest) FieldsScmGitReferences(fieldsScmGitReferences []string) ApiScmRepositoriesGetCollectionRequest {
	r.fieldsScmGitReferences = &fieldsScmGitReferences
	return r
}

// the fields to include for returned resources of type scmPullRequests
func (r ApiScmRepositoriesGetCollectionRequest) FieldsScmPullRequests(fieldsScmPullRequests []string) ApiScmRepositoriesGetCollectionRequest {
	r.fieldsScmPullRequests = &fieldsScmPullRequests
	return r
}

func (r ApiScmRepositoriesGetCollectionRequest) Execute() (*ScmRepositoriesResponse, *http.Response, error) {
	return r.ApiService.ScmRepositoriesGetCollectionExecute(r)
}

/*
ScmRepositoriesGetCollection Method for ScmRepositoriesGetCollection

	@param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
	@return ApiScmRepositoriesGetCollectionRequest
*/
func (a *ScmRepositoriesApiService) ScmRepositoriesGetCollection(ctx context.Context) ApiScmRepositoriesGetCollectionRequest {
	return ApiScmRepositoriesGetCollectionRequest{
		ApiService: a,
		ctx:        ctx,
	}
}

// Execute executes the request
//
//	@return ScmRepositoriesResponse
func (a *ScmRepositoriesApiService) ScmRepositoriesGetCollectionExecute(r ApiScmRepositoriesGetCollectionRequest) (*ScmRepositoriesResponse, *http.Response, error) {
	var (
		localVarHTTPMethod  = http.MethodGet
		localVarPostBody    interface{}
		formFiles           []formFile
		localVarReturnValue *ScmRepositoriesResponse
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "ScmRepositoriesApiService.ScmRepositoriesGetCollection")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/scmRepositories"

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}

	if r.filterId != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "filter[id]", r.filterId, "csv")
	}
	if r.fieldsScmRepositories != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "fields[scmRepositories]", r.fieldsScmRepositories, "csv")
	}
	if r.limit != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "limit", r.limit, "")
	}
	if r.include != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "include", r.include, "csv")
	}
	if r.fieldsScmGitReferences != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "fields[scmGitReferences]", r.fieldsScmGitReferences, "csv")
	}
	if r.fieldsScmPullRequests != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "fields[scmPullRequests]", r.fieldsScmPullRequests, "csv")
	}
	// to determine the Content-Type header
	localVarHTTPContentTypes := []string{}

	// set Content-Type header
	localVarHTTPContentType := selectHeaderContentType(localVarHTTPContentTypes)
	if localVarHTTPContentType != "" {
		localVarHeaderParams["Content-Type"] = localVarHTTPContentType
	}

	// to determine the Accept header
	localVarHTTPHeaderAccepts := []string{"application/json"}

	// set Accept header
	localVarHTTPHeaderAccept := selectHeaderAccept(localVarHTTPHeaderAccepts)
	if localVarHTTPHeaderAccept != "" {
		localVarHeaderParams["Accept"] = localVarHTTPHeaderAccept
	}
	req, err := a.client.prepareRequest(r.ctx, localVarPath, localVarHTTPMethod, localVarPostBody, localVarHeaderParams, localVarQueryParams, localVarFormParams, formFiles)
	if err != nil {
		return localVarReturnValue, nil, err
	}

	localVarHTTPResponse, err := a.client.callAPI(req)
	if err != nil || localVarHTTPResponse == nil {
		return localVarReturnValue, localVarHTTPResponse, err
	}

	localVarBody, err := io.ReadAll(localVarHTTPResponse.Body)
	localVarHTTPResponse.Body.Close()
	localVarHTTPResponse.Body = io.NopCloser(bytes.NewBuffer(localVarBody))
	if err != nil {
		return localVarReturnValue, localVarHTTPResponse, err
	}

	if localVarHTTPResponse.StatusCode >= 300 {
		newErr := &GenericOpenAPIError{
			body:  localVarBody,
			error: localVarHTTPResponse.Status,
		}
		if localVarHTTPResponse.StatusCode == 400 {
			var v ErrorResponse
			err = a.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarReturnValue, localVarHTTPResponse, newErr
			}
			newErr.error = formatErrorMessage(localVarHTTPResponse.Status, &v)
			newErr.model = v
			return localVarReturnValue, localVarHTTPResponse, newErr
		}
		if localVarHTTPResponse.StatusCode == 403 {
			var v ErrorResponse
			err = a.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarReturnValue, localVarHTTPResponse, newErr
			}
			newErr.error = formatErrorMessage(localVarHTTPResponse.Status, &v)
			newErr.model = v
			return localVarReturnValue, localVarHTTPResponse, newErr
		}
		return localVarReturnValue, localVarHTTPResponse, newErr
	}

	err = a.client.decode(&localVarReturnValue, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
	if err != nil {
		newErr := &GenericOpenAPIError{
			body:  localVarBody,
			error: err.Error(),
		}
		return localVarReturnValue, localVarHTTPResponse, newErr
	}

	return localVarReturnValue, localVarHTTPResponse, nil
}

type ApiScmRepositoriesGetInstanceRequest struct {
	ctx                    context.Context
	ApiService             *ScmRepositoriesApiService
	id                     string
	fieldsScmRepositories  *[]string
	include                *[]string
	fieldsScmGitReferences *[]string
	fieldsScmPullRequests  *[]string
}

// the fields to include for returned resources of type scmRepositories
func (r ApiScmRepositoriesGetInstanceRequest) FieldsScmRepositories(fieldsScmRepositories []string) ApiScmRepositoriesGetInstanceRequest {
	r.fieldsScmRepositories = &fieldsScmRepositories
	return r
}

// comma-separated list of relationships to include
func (r ApiScmRepositoriesGetInstanceRequest) Include(include []string) ApiScmRepositoriesGetInstanceRequest {
	r.include = &include
	return r
}

// the fields to include for returned resources of type scmGitReferences
func (r ApiScmRepositoriesGetInstanceRequest) FieldsScmGitReferences(fieldsScmGitReferences []string) ApiScmRepositoriesGetInstanceRequest {
	r.fieldsScmGitReferences = &fieldsScmGitReferences
	return r
}

// the fields to include for returned resources of type scmPullRequests
func (r ApiScmRepositoriesGetInstanceRequest) FieldsScmPullRequests(fieldsScmPullRequests []string) ApiScmRepositoriesGetInstanceRequest {
	r.fieldsScmPullRequests = &fieldsScmPullRequests
	return r
}

func (r ApiScmRepositoriesGetInstanceRequest) Execute() (*ScmRepositoryResponse, *http.Response, error) {
	return r.ApiService.ScmRepositoriesGetInstanceExecute(r)
}

/*
ScmRepositoriesGetInstance Method for ScmRepositoriesGetInstance

	@param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
	@param id the id of the requested resource
	@return ApiScmRepositoriesGetInstanceRequest
*/
func (a *ScmRepositoriesApiService) ScmRepositoriesGetInstance(ctx context.Context, id string) ApiScmRepositoriesGetInstanceRequest {
	return ApiScmRepositoriesGetInstanceRequest{
		ApiService: a,
		ctx:        ctx,
		id:         id,
	}
}

// Execute executes the request
//
//	@return ScmRepositoryResponse
func (a *ScmRepositoriesApiService) ScmRepositoriesGetInstanceExecute(r ApiScmRepositoriesGetInstanceRequest) (*ScmRepositoryResponse, *http.Response, error) {
	var (
		localVarHTTPMethod  = http.MethodGet
		localVarPostBody    interface{}
		formFiles           []formFile
		localVarReturnValue *ScmRepositoryResponse
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "ScmRepositoriesApiService.ScmRepositoriesGetInstance")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/scmRepositories/{id}"
	localVarPath = strings.Replace(localVarPath, "{"+"id"+"}", url.PathEscape(parameterValueToString(r.id, "id")), -1)

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}

	if r.fieldsScmRepositories != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "fields[scmRepositories]", r.fieldsScmRepositories, "csv")
	}
	if r.include != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "include", r.include, "csv")
	}
	if r.fieldsScmGitReferences != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "fields[scmGitReferences]", r.fieldsScmGitReferences, "csv")
	}
	if r.fieldsScmPullRequests != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "fields[scmPullRequests]", r.fieldsScmPullRequests, "csv")
	}
	// to determine the Content-Type header
	localVarHTTPContentTypes := []string{}

	// set Content-Type header
	localVarHTTPContentType := selectHeaderContentType(localVarHTTPContentTypes)
	if localVarHTTPContentType != "" {
		localVarHeaderParams["Content-Type"] = localVarHTTPContentType
	}

	// to determine the Accept header
	localVarHTTPHeaderAccepts := []string{"application/json"}

	// set Accept header
	localVarHTTPHeaderAccept := selectHeaderAccept(localVarHTTPHeaderAccepts)
	if localVarHTTPHeaderAccept != "" {
		localVarHeaderParams["Accept"] = localVarHTTPHeaderAccept
	}
	req, err := a.client.prepareRequest(r.ctx, localVarPath, localVarHTTPMethod, localVarPostBody, localVarHeaderParams, localVarQueryParams, localVarFormParams, formFiles)
	if err != nil {
		return localVarReturnValue, nil, err
	}

	localVarHTTPResponse, err := a.client.callAPI(req)
	if err != nil || localVarHTTPResponse == nil {
		return localVarReturnValue, localVarHTTPResponse, err
	}

	localVarBody, err := io.ReadAll(localVarHTTPResponse.Body)
	localVarHTTPResponse.Body.Close()
	localVarHTTPResponse.Body = io.NopCloser(bytes.NewBuffer(localVarBody))
	if err != nil {
		return localVarReturnValue, localVarHTTPResponse, err
	}

	if localVarHTTPResponse.StatusCode >= 300 {
		newErr := &GenericOpenAPIError{
			body:  localVarBody,
			error: localVarHTTPResponse.Status,
		}
		if localVarHTTPResponse.StatusCode == 400 {
			var v ErrorResponse
			err = a.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarReturnValue, localVarHTTPResponse, newErr
			}
			newErr.error = formatErrorMessage(localVarHTTPResponse.Status, &v)
			newErr.model = v
			return localVarReturnValue, localVarHTTPResponse, newErr
		}
		if localVarHTTPResponse.StatusCode == 403 {
			var v ErrorResponse
			err = a.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarReturnValue, localVarHTTPResponse, newErr
			}
			newErr.error = formatErrorMessage(localVarHTTPResponse.Status, &v)
			newErr.model = v
			return localVarReturnValue, localVarHTTPResponse, newErr
		}
		if localVarHTTPResponse.StatusCode == 404 {
			var v ErrorResponse
			err = a.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarReturnValue, localVarHTTPResponse, newErr
			}
			newErr.error = formatErrorMessage(localVarHTTPResponse.Status, &v)
			newErr.model = v
			return localVarReturnValue, localVarHTTPResponse, newErr
		}
		return localVarReturnValue, localVarHTTPResponse, newErr
	}

	err = a.client.decode(&localVarReturnValue, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
	if err != nil {
		newErr := &GenericOpenAPIError{
			body:  localVarBody,
			error: err.Error(),
		}
		return localVarReturnValue, localVarHTTPResponse, newErr
	}

	return localVarReturnValue, localVarHTTPResponse, nil
}

type ApiScmRepositoriesGitReferencesGetToManyRelatedRequest struct {
	ctx                    context.Context
	ApiService             *ScmRepositoriesApiService
	id                     string
	fieldsScmGitReferences *[]string
	fieldsScmRepositories  *[]string
	limit                  *int32
	include                *[]string
}

// the fields to include for returned resources of type scmGitReferences
func (r ApiScmRepositoriesGitReferencesGetToManyRelatedRequest) FieldsScmGitReferences(fieldsScmGitReferences []string) ApiScmRepositoriesGitReferencesGetToManyRelatedRequest {
	r.fieldsScmGitReferences = &fieldsScmGitReferences
	return r
}

// the fields to include for returned resources of type scmRepositories
func (r ApiScmRepositoriesGitReferencesGetToManyRelatedRequest) FieldsScmRepositories(fieldsScmRepositories []string) ApiScmRepositoriesGitReferencesGetToManyRelatedRequest {
	r.fieldsScmRepositories = &fieldsScmRepositories
	return r
}

// maximum resources per page
func (r ApiScmRepositoriesGitReferencesGetToManyRelatedRequest) Limit(limit int32) ApiScmRepositoriesGitReferencesGetToManyRelatedRequest {
	r.limit = &limit
	return r
}

// comma-separated list of relationships to include
func (r ApiScmRepositoriesGitReferencesGetToManyRelatedRequest) Include(include []string) ApiScmRepositoriesGitReferencesGetToManyRelatedRequest {
	r.include = &include
	return r
}

func (r ApiScmRepositoriesGitReferencesGetToManyRelatedRequest) Execute() (*ScmGitReferencesResponse, *http.Response, error) {
	return r.ApiService.ScmRepositoriesGitReferencesGetToManyRelatedExecute(r)
}

/*
ScmRepositoriesGitReferencesGetToManyRelated Method for ScmRepositoriesGitReferencesGetToManyRelated

	@param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
	@param id the id of the requested resource
	@return ApiScmRepositoriesGitReferencesGetToManyRelatedRequest
*/
func (a *ScmRepositoriesApiService) ScmRepositoriesGitReferencesGetToManyRelated(ctx context.Context, id string) ApiScmRepositoriesGitReferencesGetToManyRelatedRequest {
	return ApiScmRepositoriesGitReferencesGetToManyRelatedRequest{
		ApiService: a,
		ctx:        ctx,
		id:         id,
	}
}

// Execute executes the request
//
//	@return ScmGitReferencesResponse
func (a *ScmRepositoriesApiService) ScmRepositoriesGitReferencesGetToManyRelatedExecute(r ApiScmRepositoriesGitReferencesGetToManyRelatedRequest) (*ScmGitReferencesResponse, *http.Response, error) {
	var (
		localVarHTTPMethod  = http.MethodGet
		localVarPostBody    interface{}
		formFiles           []formFile
		localVarReturnValue *ScmGitReferencesResponse
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "ScmRepositoriesApiService.ScmRepositoriesGitReferencesGetToManyRelated")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/scmRepositories/{id}/gitReferences"
	localVarPath = strings.Replace(localVarPath, "{"+"id"+"}", url.PathEscape(parameterValueToString(r.id, "id")), -1)

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}

	if r.fieldsScmGitReferences != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "fields[scmGitReferences]", r.fieldsScmGitReferences, "csv")
	}
	if r.fieldsScmRepositories != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "fields[scmRepositories]", r.fieldsScmRepositories, "csv")
	}
	if r.limit != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "limit", r.limit, "")
	}
	if r.include != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "include", r.include, "csv")
	}
	// to determine the Content-Type header
	localVarHTTPContentTypes := []string{}

	// set Content-Type header
	localVarHTTPContentType := selectHeaderContentType(localVarHTTPContentTypes)
	if localVarHTTPContentType != "" {
		localVarHeaderParams["Content-Type"] = localVarHTTPContentType
	}

	// to determine the Accept header
	localVarHTTPHeaderAccepts := []string{"application/json"}

	// set Accept header
	localVarHTTPHeaderAccept := selectHeaderAccept(localVarHTTPHeaderAccepts)
	if localVarHTTPHeaderAccept != "" {
		localVarHeaderParams["Accept"] = localVarHTTPHeaderAccept
	}
	req, err := a.client.prepareRequest(r.ctx, localVarPath, localVarHTTPMethod, localVarPostBody, localVarHeaderParams, localVarQueryParams, localVarFormParams, formFiles)
	if err != nil {
		return localVarReturnValue, nil, err
	}

	localVarHTTPResponse, err := a.client.callAPI(req)
	if err != nil || localVarHTTPResponse == nil {
		return localVarReturnValue, localVarHTTPResponse, err
	}

	localVarBody, err := io.ReadAll(localVarHTTPResponse.Body)
	localVarHTTPResponse.Body.Close()
	localVarHTTPResponse.Body = io.NopCloser(bytes.NewBuffer(localVarBody))
	if err != nil {
		return localVarReturnValue, localVarHTTPResponse, err
	}

	if localVarHTTPResponse.StatusCode >= 300 {
		newErr := &GenericOpenAPIError{
			body:  localVarBody,
			error: localVarHTTPResponse.Status,
		}
		if localVarHTTPResponse.StatusCode == 400 {
			var v ErrorResponse
			err = a.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarReturnValue, localVarHTTPResponse, newErr
			}
			newErr.error = formatErrorMessage(localVarHTTPResponse.Status, &v)
			newErr.model = v
			return localVarReturnValue, localVarHTTPResponse, newErr
		}
		if localVarHTTPResponse.StatusCode == 403 {
			var v ErrorResponse
			err = a.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarReturnValue, localVarHTTPResponse, newErr
			}
			newErr.error = formatErrorMessage(localVarHTTPResponse.Status, &v)
			newErr.model = v
			return localVarReturnValue, localVarHTTPResponse, newErr
		}
		if localVarHTTPResponse.StatusCode == 404 {
			var v ErrorResponse
			err = a.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarReturnValue, localVarHTTPResponse, newErr
			}
			newErr.error = formatErrorMessage(localVarHTTPResponse.Status, &v)
			newErr.model = v
			return localVarReturnValue, localVarHTTPResponse, newErr
		}
		return localVarReturnValue, localVarHTTPResponse, newErr
	}

	err = a.client.decode(&localVarReturnValue, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
	if err != nil {
		newErr := &GenericOpenAPIError{
			body:  localVarBody,
			error: err.Error(),
		}
		return localVarReturnValue, localVarHTTPResponse, newErr
	}

	return localVarReturnValue, localVarHTTPResponse, nil
}

type ApiScmRepositoriesPullRequestsGetToManyRelatedRequest struct {
	ctx                   context.Context
	ApiService            *ScmRepositoriesApiService
	id                    string
	fieldsScmPullRequests *[]string
	fieldsScmRepositories *[]string
	limit                 *int32
	include               *[]string
}

// the fields to include for returned resources of type scmPullRequests
func (r ApiScmRepositoriesPullRequestsGetToManyRelatedRequest) FieldsScmPullRequests(fieldsScmPullRequests []string) ApiScmRepositoriesPullRequestsGetToManyRelatedRequest {
	r.fieldsScmPullRequests = &fieldsScmPullRequests
	return r
}

// the fields to include for returned resources of type scmRepositories
func (r ApiScmRepositoriesPullRequestsGetToManyRelatedRequest) FieldsScmRepositories(fieldsScmRepositories []string) ApiScmRepositoriesPullRequestsGetToManyRelatedRequest {
	r.fieldsScmRepositories = &fieldsScmRepositories
	return r
}

// maximum resources per page
func (r ApiScmRepositoriesPullRequestsGetToManyRelatedRequest) Limit(limit int32) ApiScmRepositoriesPullRequestsGetToManyRelatedRequest {
	r.limit = &limit
	return r
}

// comma-separated list of relationships to include
func (r ApiScmRepositoriesPullRequestsGetToManyRelatedRequest) Include(include []string) ApiScmRepositoriesPullRequestsGetToManyRelatedRequest {
	r.include = &include
	return r
}

func (r ApiScmRepositoriesPullRequestsGetToManyRelatedRequest) Execute() (*ScmPullRequestsResponse, *http.Response, error) {
	return r.ApiService.ScmRepositoriesPullRequestsGetToManyRelatedExecute(r)
}

/*
ScmRepositoriesPullRequestsGetToManyRelated Method for ScmRepositoriesPullRequestsGetToManyRelated

	@param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
	@param id the id of the requested resource
	@return ApiScmRepositoriesPullRequestsGetToManyRelatedRequest
*/
func (a *ScmRepositoriesApiService) ScmRepositoriesPullRequestsGetToManyRelated(ctx context.Context, id string) ApiScmRepositoriesPullRequestsGetToManyRelatedRequest {
	return ApiScmRepositoriesPullRequestsGetToManyRelatedRequest{
		ApiService: a,
		ctx:        ctx,
		id:         id,
	}
}

// Execute executes the request
//
//	@return ScmPullRequestsResponse
func (a *ScmRepositoriesApiService) ScmRepositoriesPullRequestsGetToManyRelatedExecute(r ApiScmRepositoriesPullRequestsGetToManyRelatedRequest) (*ScmPullRequestsResponse, *http.Response, error) {
	var (
		localVarHTTPMethod  = http.MethodGet
		localVarPostBody    interface{}
		formFiles           []formFile
		localVarReturnValue *ScmPullRequestsResponse
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "ScmRepositoriesApiService.ScmRepositoriesPullRequestsGetToManyRelated")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/scmRepositories/{id}/pullRequests"
	localVarPath = strings.Replace(localVarPath, "{"+"id"+"}", url.PathEscape(parameterValueToString(r.id, "id")), -1)

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}

	if r.fieldsScmPullRequests != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "fields[scmPullRequests]", r.fieldsScmPullRequests, "csv")
	}
	if r.fieldsScmRepositories != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "fields[scmRepositories]", r.fieldsScmRepositories, "csv")
	}
	if r.limit != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "limit", r.limit, "")
	}
	if r.include != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "include", r.include, "csv")
	}
	// to determine the Content-Type header
	localVarHTTPContentTypes := []string{}

	// set Content-Type header
	localVarHTTPContentType := selectHeaderContentType(localVarHTTPContentTypes)
	if localVarHTTPContentType != "" {
		localVarHeaderParams["Content-Type"] = localVarHTTPContentType
	}

	// to determine the Accept header
	localVarHTTPHeaderAccepts := []string{"application/json"}

	// set Accept header
	localVarHTTPHeaderAccept := selectHeaderAccept(localVarHTTPHeaderAccepts)
	if localVarHTTPHeaderAccept != "" {
		localVarHeaderParams["Accept"] = localVarHTTPHeaderAccept
	}
	req, err := a.client.prepareRequest(r.ctx, localVarPath, localVarHTTPMethod, localVarPostBody, localVarHeaderParams, localVarQueryParams, localVarFormParams, formFiles)
	if err != nil {
		return localVarReturnValue, nil, err
	}

	localVarHTTPResponse, err := a.client.callAPI(req)
	if err != nil || localVarHTTPResponse == nil {
		return localVarReturnValue, localVarHTTPResponse, err
	}

	localVarBody, err := io.ReadAll(localVarHTTPResponse.Body)
	localVarHTTPResponse.Body.Close()
	localVarHTTPResponse.Body = io.NopCloser(bytes.NewBuffer(localVarBody))
	if err != nil {
		return localVarReturnValue, localVarHTTPResponse, err
	}

	if localVarHTTPResponse.StatusCode >= 300 {
		newErr := &GenericOpenAPIError{
			body:  localVarBody,
			error: localVarHTTPResponse.Status,
		}
		if localVarHTTPResponse.StatusCode == 400 {
			var v ErrorResponse
			err = a.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarReturnValue, localVarHTTPResponse, newErr
			}
			newErr.error = formatErrorMessage(localVarHTTPResponse.Status, &v)
			newErr.model = v
			return localVarReturnValue, localVarHTTPResponse, newErr
		}
		if localVarHTTPResponse.StatusCode == 403 {
			var v ErrorResponse
			err = a.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarReturnValue, localVarHTTPResponse, newErr
			}
			newErr.error = formatErrorMessage(localVarHTTPResponse.Status, &v)
			newErr.model = v
			return localVarReturnValue, localVarHTTPResponse, newErr
		}
		if localVarHTTPResponse.StatusCode == 404 {
			var v ErrorResponse
			err = a.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarReturnValue, localVarHTTPResponse, newErr
			}
			newErr.error = formatErrorMessage(localVarHTTPResponse.Status, &v)
			newErr.model = v
			return localVarReturnValue, localVarHTTPResponse, newErr
		}
		return localVarReturnValue, localVarHTTPResponse, newErr
	}

	err = a.client.decode(&localVarReturnValue, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
	if err != nil {
		newErr := &GenericOpenAPIError{
			body:  localVarBody,
			error: err.Error(),
		}
		return localVarReturnValue, localVarHTTPResponse, newErr
	}

	return localVarReturnValue, localVarHTTPResponse, nil
}
