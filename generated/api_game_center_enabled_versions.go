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

// GameCenterEnabledVersionsApiService GameCenterEnabledVersionsApi service
type GameCenterEnabledVersionsApiService service

type ApiGameCenterEnabledVersionsCompatibleVersionsCreateToManyRelationshipRequest struct {
	ctx                                                       context.Context
	ApiService                                                *GameCenterEnabledVersionsApiService
	id                                                        string
	gameCenterEnabledVersionCompatibleVersionsLinkagesRequest *GameCenterEnabledVersionCompatibleVersionsLinkagesRequest
}

// List of related linkages
func (r ApiGameCenterEnabledVersionsCompatibleVersionsCreateToManyRelationshipRequest) GameCenterEnabledVersionCompatibleVersionsLinkagesRequest(gameCenterEnabledVersionCompatibleVersionsLinkagesRequest GameCenterEnabledVersionCompatibleVersionsLinkagesRequest) ApiGameCenterEnabledVersionsCompatibleVersionsCreateToManyRelationshipRequest {
	r.gameCenterEnabledVersionCompatibleVersionsLinkagesRequest = &gameCenterEnabledVersionCompatibleVersionsLinkagesRequest
	return r
}

func (r ApiGameCenterEnabledVersionsCompatibleVersionsCreateToManyRelationshipRequest) Execute() (*http.Response, error) {
	return r.ApiService.GameCenterEnabledVersionsCompatibleVersionsCreateToManyRelationshipExecute(r)
}

/*
GameCenterEnabledVersionsCompatibleVersionsCreateToManyRelationship Method for GameCenterEnabledVersionsCompatibleVersionsCreateToManyRelationship

	@param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
	@param id the id of the requested resource
	@return ApiGameCenterEnabledVersionsCompatibleVersionsCreateToManyRelationshipRequest
*/
func (a *GameCenterEnabledVersionsApiService) GameCenterEnabledVersionsCompatibleVersionsCreateToManyRelationship(ctx context.Context, id string) ApiGameCenterEnabledVersionsCompatibleVersionsCreateToManyRelationshipRequest {
	return ApiGameCenterEnabledVersionsCompatibleVersionsCreateToManyRelationshipRequest{
		ApiService: a,
		ctx:        ctx,
		id:         id,
	}
}

// Execute executes the request
func (a *GameCenterEnabledVersionsApiService) GameCenterEnabledVersionsCompatibleVersionsCreateToManyRelationshipExecute(r ApiGameCenterEnabledVersionsCompatibleVersionsCreateToManyRelationshipRequest) (*http.Response, error) {
	var (
		localVarHTTPMethod = http.MethodPost
		localVarPostBody   interface{}
		formFiles          []formFile
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "GameCenterEnabledVersionsApiService.GameCenterEnabledVersionsCompatibleVersionsCreateToManyRelationship")
	if err != nil {
		return nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/gameCenterEnabledVersions/{id}/relationships/compatibleVersions"
	localVarPath = strings.Replace(localVarPath, "{"+"id"+"}", url.PathEscape(parameterValueToString(r.id, "id")), -1)

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}
	if r.gameCenterEnabledVersionCompatibleVersionsLinkagesRequest == nil {
		return nil, reportError("gameCenterEnabledVersionCompatibleVersionsLinkagesRequest is required and must be specified")
	}

	// to determine the Content-Type header
	localVarHTTPContentTypes := []string{"application/json"}

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
	// body params
	localVarPostBody = r.gameCenterEnabledVersionCompatibleVersionsLinkagesRequest
	req, err := a.client.prepareRequest(r.ctx, localVarPath, localVarHTTPMethod, localVarPostBody, localVarHeaderParams, localVarQueryParams, localVarFormParams, formFiles)
	if err != nil {
		return nil, err
	}

	localVarHTTPResponse, err := a.client.callAPI(req)
	if err != nil || localVarHTTPResponse == nil {
		return localVarHTTPResponse, err
	}

	localVarBody, err := io.ReadAll(localVarHTTPResponse.Body)
	localVarHTTPResponse.Body.Close()
	localVarHTTPResponse.Body = io.NopCloser(bytes.NewBuffer(localVarBody))
	if err != nil {
		return localVarHTTPResponse, err
	}

	if localVarHTTPResponse.StatusCode >= 300 {
		newErr := &GenericOpenAPIError{
			body:  localVarBody,
			error: localVarHTTPResponse.Status,
		}
		if localVarHTTPResponse.StatusCode == 403 {
			var v ErrorResponse
			err = a.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarHTTPResponse, newErr
			}
			newErr.error = formatErrorMessage(localVarHTTPResponse.Status, &v)
			newErr.model = v
			return localVarHTTPResponse, newErr
		}
		if localVarHTTPResponse.StatusCode == 404 {
			var v ErrorResponse
			err = a.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarHTTPResponse, newErr
			}
			newErr.error = formatErrorMessage(localVarHTTPResponse.Status, &v)
			newErr.model = v
			return localVarHTTPResponse, newErr
		}
		if localVarHTTPResponse.StatusCode == 409 {
			var v ErrorResponse
			err = a.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarHTTPResponse, newErr
			}
			newErr.error = formatErrorMessage(localVarHTTPResponse.Status, &v)
			newErr.model = v
			return localVarHTTPResponse, newErr
		}
		return localVarHTTPResponse, newErr
	}

	return localVarHTTPResponse, nil
}

type ApiGameCenterEnabledVersionsCompatibleVersionsDeleteToManyRelationshipRequest struct {
	ctx                                                       context.Context
	ApiService                                                *GameCenterEnabledVersionsApiService
	id                                                        string
	gameCenterEnabledVersionCompatibleVersionsLinkagesRequest *GameCenterEnabledVersionCompatibleVersionsLinkagesRequest
}

// List of related linkages
func (r ApiGameCenterEnabledVersionsCompatibleVersionsDeleteToManyRelationshipRequest) GameCenterEnabledVersionCompatibleVersionsLinkagesRequest(gameCenterEnabledVersionCompatibleVersionsLinkagesRequest GameCenterEnabledVersionCompatibleVersionsLinkagesRequest) ApiGameCenterEnabledVersionsCompatibleVersionsDeleteToManyRelationshipRequest {
	r.gameCenterEnabledVersionCompatibleVersionsLinkagesRequest = &gameCenterEnabledVersionCompatibleVersionsLinkagesRequest
	return r
}

func (r ApiGameCenterEnabledVersionsCompatibleVersionsDeleteToManyRelationshipRequest) Execute() (*http.Response, error) {
	return r.ApiService.GameCenterEnabledVersionsCompatibleVersionsDeleteToManyRelationshipExecute(r)
}

/*
GameCenterEnabledVersionsCompatibleVersionsDeleteToManyRelationship Method for GameCenterEnabledVersionsCompatibleVersionsDeleteToManyRelationship

	@param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
	@param id the id of the requested resource
	@return ApiGameCenterEnabledVersionsCompatibleVersionsDeleteToManyRelationshipRequest
*/
func (a *GameCenterEnabledVersionsApiService) GameCenterEnabledVersionsCompatibleVersionsDeleteToManyRelationship(ctx context.Context, id string) ApiGameCenterEnabledVersionsCompatibleVersionsDeleteToManyRelationshipRequest {
	return ApiGameCenterEnabledVersionsCompatibleVersionsDeleteToManyRelationshipRequest{
		ApiService: a,
		ctx:        ctx,
		id:         id,
	}
}

// Execute executes the request
func (a *GameCenterEnabledVersionsApiService) GameCenterEnabledVersionsCompatibleVersionsDeleteToManyRelationshipExecute(r ApiGameCenterEnabledVersionsCompatibleVersionsDeleteToManyRelationshipRequest) (*http.Response, error) {
	var (
		localVarHTTPMethod = http.MethodDelete
		localVarPostBody   interface{}
		formFiles          []formFile
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "GameCenterEnabledVersionsApiService.GameCenterEnabledVersionsCompatibleVersionsDeleteToManyRelationship")
	if err != nil {
		return nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/gameCenterEnabledVersions/{id}/relationships/compatibleVersions"
	localVarPath = strings.Replace(localVarPath, "{"+"id"+"}", url.PathEscape(parameterValueToString(r.id, "id")), -1)

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}
	if r.gameCenterEnabledVersionCompatibleVersionsLinkagesRequest == nil {
		return nil, reportError("gameCenterEnabledVersionCompatibleVersionsLinkagesRequest is required and must be specified")
	}

	// to determine the Content-Type header
	localVarHTTPContentTypes := []string{"application/json"}

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
	// body params
	localVarPostBody = r.gameCenterEnabledVersionCompatibleVersionsLinkagesRequest
	req, err := a.client.prepareRequest(r.ctx, localVarPath, localVarHTTPMethod, localVarPostBody, localVarHeaderParams, localVarQueryParams, localVarFormParams, formFiles)
	if err != nil {
		return nil, err
	}

	localVarHTTPResponse, err := a.client.callAPI(req)
	if err != nil || localVarHTTPResponse == nil {
		return localVarHTTPResponse, err
	}

	localVarBody, err := io.ReadAll(localVarHTTPResponse.Body)
	localVarHTTPResponse.Body.Close()
	localVarHTTPResponse.Body = io.NopCloser(bytes.NewBuffer(localVarBody))
	if err != nil {
		return localVarHTTPResponse, err
	}

	if localVarHTTPResponse.StatusCode >= 300 {
		newErr := &GenericOpenAPIError{
			body:  localVarBody,
			error: localVarHTTPResponse.Status,
		}
		if localVarHTTPResponse.StatusCode == 403 {
			var v ErrorResponse
			err = a.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarHTTPResponse, newErr
			}
			newErr.error = formatErrorMessage(localVarHTTPResponse.Status, &v)
			newErr.model = v
			return localVarHTTPResponse, newErr
		}
		if localVarHTTPResponse.StatusCode == 404 {
			var v ErrorResponse
			err = a.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarHTTPResponse, newErr
			}
			newErr.error = formatErrorMessage(localVarHTTPResponse.Status, &v)
			newErr.model = v
			return localVarHTTPResponse, newErr
		}
		if localVarHTTPResponse.StatusCode == 409 {
			var v ErrorResponse
			err = a.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarHTTPResponse, newErr
			}
			newErr.error = formatErrorMessage(localVarHTTPResponse.Status, &v)
			newErr.model = v
			return localVarHTTPResponse, newErr
		}
		return localVarHTTPResponse, newErr
	}

	return localVarHTTPResponse, nil
}

type ApiGameCenterEnabledVersionsCompatibleVersionsGetToManyRelatedRequest struct {
	ctx                             context.Context
	ApiService                      *GameCenterEnabledVersionsApiService
	id                              string
	filterPlatform                  *[]string
	filterVersionString             *[]string
	filterApp                       *[]string
	filterId                        *[]string
	sort                            *[]string
	fieldsGameCenterEnabledVersions *[]string
	fieldsApps                      *[]string
	limit                           *int32
	limitCompatibleVersions         *int32
	include                         *[]string
}

// filter by attribute &#39;platform&#39;
func (r ApiGameCenterEnabledVersionsCompatibleVersionsGetToManyRelatedRequest) FilterPlatform(filterPlatform []string) ApiGameCenterEnabledVersionsCompatibleVersionsGetToManyRelatedRequest {
	r.filterPlatform = &filterPlatform
	return r
}

// filter by attribute &#39;versionString&#39;
func (r ApiGameCenterEnabledVersionsCompatibleVersionsGetToManyRelatedRequest) FilterVersionString(filterVersionString []string) ApiGameCenterEnabledVersionsCompatibleVersionsGetToManyRelatedRequest {
	r.filterVersionString = &filterVersionString
	return r
}

// filter by id(s) of related &#39;app&#39;
func (r ApiGameCenterEnabledVersionsCompatibleVersionsGetToManyRelatedRequest) FilterApp(filterApp []string) ApiGameCenterEnabledVersionsCompatibleVersionsGetToManyRelatedRequest {
	r.filterApp = &filterApp
	return r
}

// filter by id(s)
func (r ApiGameCenterEnabledVersionsCompatibleVersionsGetToManyRelatedRequest) FilterId(filterId []string) ApiGameCenterEnabledVersionsCompatibleVersionsGetToManyRelatedRequest {
	r.filterId = &filterId
	return r
}

// comma-separated list of sort expressions; resources will be sorted as specified
func (r ApiGameCenterEnabledVersionsCompatibleVersionsGetToManyRelatedRequest) Sort(sort []string) ApiGameCenterEnabledVersionsCompatibleVersionsGetToManyRelatedRequest {
	r.sort = &sort
	return r
}

// the fields to include for returned resources of type gameCenterEnabledVersions
func (r ApiGameCenterEnabledVersionsCompatibleVersionsGetToManyRelatedRequest) FieldsGameCenterEnabledVersions(fieldsGameCenterEnabledVersions []string) ApiGameCenterEnabledVersionsCompatibleVersionsGetToManyRelatedRequest {
	r.fieldsGameCenterEnabledVersions = &fieldsGameCenterEnabledVersions
	return r
}

// the fields to include for returned resources of type apps
func (r ApiGameCenterEnabledVersionsCompatibleVersionsGetToManyRelatedRequest) FieldsApps(fieldsApps []string) ApiGameCenterEnabledVersionsCompatibleVersionsGetToManyRelatedRequest {
	r.fieldsApps = &fieldsApps
	return r
}

// maximum resources per page
func (r ApiGameCenterEnabledVersionsCompatibleVersionsGetToManyRelatedRequest) Limit(limit int32) ApiGameCenterEnabledVersionsCompatibleVersionsGetToManyRelatedRequest {
	r.limit = &limit
	return r
}

// maximum number of related compatibleVersions returned (when they are included)
func (r ApiGameCenterEnabledVersionsCompatibleVersionsGetToManyRelatedRequest) LimitCompatibleVersions(limitCompatibleVersions int32) ApiGameCenterEnabledVersionsCompatibleVersionsGetToManyRelatedRequest {
	r.limitCompatibleVersions = &limitCompatibleVersions
	return r
}

// comma-separated list of relationships to include
func (r ApiGameCenterEnabledVersionsCompatibleVersionsGetToManyRelatedRequest) Include(include []string) ApiGameCenterEnabledVersionsCompatibleVersionsGetToManyRelatedRequest {
	r.include = &include
	return r
}

func (r ApiGameCenterEnabledVersionsCompatibleVersionsGetToManyRelatedRequest) Execute() (*GameCenterEnabledVersionsResponse, *http.Response, error) {
	return r.ApiService.GameCenterEnabledVersionsCompatibleVersionsGetToManyRelatedExecute(r)
}

/*
GameCenterEnabledVersionsCompatibleVersionsGetToManyRelated Method for GameCenterEnabledVersionsCompatibleVersionsGetToManyRelated

	@param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
	@param id the id of the requested resource
	@return ApiGameCenterEnabledVersionsCompatibleVersionsGetToManyRelatedRequest
*/
func (a *GameCenterEnabledVersionsApiService) GameCenterEnabledVersionsCompatibleVersionsGetToManyRelated(ctx context.Context, id string) ApiGameCenterEnabledVersionsCompatibleVersionsGetToManyRelatedRequest {
	return ApiGameCenterEnabledVersionsCompatibleVersionsGetToManyRelatedRequest{
		ApiService: a,
		ctx:        ctx,
		id:         id,
	}
}

// Execute executes the request
//
//	@return GameCenterEnabledVersionsResponse
func (a *GameCenterEnabledVersionsApiService) GameCenterEnabledVersionsCompatibleVersionsGetToManyRelatedExecute(r ApiGameCenterEnabledVersionsCompatibleVersionsGetToManyRelatedRequest) (*GameCenterEnabledVersionsResponse, *http.Response, error) {
	var (
		localVarHTTPMethod  = http.MethodGet
		localVarPostBody    interface{}
		formFiles           []formFile
		localVarReturnValue *GameCenterEnabledVersionsResponse
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "GameCenterEnabledVersionsApiService.GameCenterEnabledVersionsCompatibleVersionsGetToManyRelated")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/gameCenterEnabledVersions/{id}/compatibleVersions"
	localVarPath = strings.Replace(localVarPath, "{"+"id"+"}", url.PathEscape(parameterValueToString(r.id, "id")), -1)

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}

	if r.filterPlatform != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "filter[platform]", r.filterPlatform, "csv")
	}
	if r.filterVersionString != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "filter[versionString]", r.filterVersionString, "csv")
	}
	if r.filterApp != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "filter[app]", r.filterApp, "csv")
	}
	if r.filterId != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "filter[id]", r.filterId, "csv")
	}
	if r.sort != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "sort", r.sort, "csv")
	}
	if r.fieldsGameCenterEnabledVersions != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "fields[gameCenterEnabledVersions]", r.fieldsGameCenterEnabledVersions, "csv")
	}
	if r.fieldsApps != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "fields[apps]", r.fieldsApps, "csv")
	}
	if r.limit != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "limit", r.limit, "")
	}
	if r.limitCompatibleVersions != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "limit[compatibleVersions]", r.limitCompatibleVersions, "")
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

type ApiGameCenterEnabledVersionsCompatibleVersionsGetToManyRelationshipRequest struct {
	ctx        context.Context
	ApiService *GameCenterEnabledVersionsApiService
	id         string
	limit      *int32
}

// maximum resources per page
func (r ApiGameCenterEnabledVersionsCompatibleVersionsGetToManyRelationshipRequest) Limit(limit int32) ApiGameCenterEnabledVersionsCompatibleVersionsGetToManyRelationshipRequest {
	r.limit = &limit
	return r
}

func (r ApiGameCenterEnabledVersionsCompatibleVersionsGetToManyRelationshipRequest) Execute() (*GameCenterEnabledVersionCompatibleVersionsLinkagesResponse, *http.Response, error) {
	return r.ApiService.GameCenterEnabledVersionsCompatibleVersionsGetToManyRelationshipExecute(r)
}

/*
GameCenterEnabledVersionsCompatibleVersionsGetToManyRelationship Method for GameCenterEnabledVersionsCompatibleVersionsGetToManyRelationship

	@param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
	@param id the id of the requested resource
	@return ApiGameCenterEnabledVersionsCompatibleVersionsGetToManyRelationshipRequest
*/
func (a *GameCenterEnabledVersionsApiService) GameCenterEnabledVersionsCompatibleVersionsGetToManyRelationship(ctx context.Context, id string) ApiGameCenterEnabledVersionsCompatibleVersionsGetToManyRelationshipRequest {
	return ApiGameCenterEnabledVersionsCompatibleVersionsGetToManyRelationshipRequest{
		ApiService: a,
		ctx:        ctx,
		id:         id,
	}
}

// Execute executes the request
//
//	@return GameCenterEnabledVersionCompatibleVersionsLinkagesResponse
func (a *GameCenterEnabledVersionsApiService) GameCenterEnabledVersionsCompatibleVersionsGetToManyRelationshipExecute(r ApiGameCenterEnabledVersionsCompatibleVersionsGetToManyRelationshipRequest) (*GameCenterEnabledVersionCompatibleVersionsLinkagesResponse, *http.Response, error) {
	var (
		localVarHTTPMethod  = http.MethodGet
		localVarPostBody    interface{}
		formFiles           []formFile
		localVarReturnValue *GameCenterEnabledVersionCompatibleVersionsLinkagesResponse
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "GameCenterEnabledVersionsApiService.GameCenterEnabledVersionsCompatibleVersionsGetToManyRelationship")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/gameCenterEnabledVersions/{id}/relationships/compatibleVersions"
	localVarPath = strings.Replace(localVarPath, "{"+"id"+"}", url.PathEscape(parameterValueToString(r.id, "id")), -1)

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}

	if r.limit != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "limit", r.limit, "")
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

type ApiGameCenterEnabledVersionsCompatibleVersionsReplaceToManyRelationshipRequest struct {
	ctx                                                       context.Context
	ApiService                                                *GameCenterEnabledVersionsApiService
	id                                                        string
	gameCenterEnabledVersionCompatibleVersionsLinkagesRequest *GameCenterEnabledVersionCompatibleVersionsLinkagesRequest
}

// List of related linkages
func (r ApiGameCenterEnabledVersionsCompatibleVersionsReplaceToManyRelationshipRequest) GameCenterEnabledVersionCompatibleVersionsLinkagesRequest(gameCenterEnabledVersionCompatibleVersionsLinkagesRequest GameCenterEnabledVersionCompatibleVersionsLinkagesRequest) ApiGameCenterEnabledVersionsCompatibleVersionsReplaceToManyRelationshipRequest {
	r.gameCenterEnabledVersionCompatibleVersionsLinkagesRequest = &gameCenterEnabledVersionCompatibleVersionsLinkagesRequest
	return r
}

func (r ApiGameCenterEnabledVersionsCompatibleVersionsReplaceToManyRelationshipRequest) Execute() (*http.Response, error) {
	return r.ApiService.GameCenterEnabledVersionsCompatibleVersionsReplaceToManyRelationshipExecute(r)
}

/*
GameCenterEnabledVersionsCompatibleVersionsReplaceToManyRelationship Method for GameCenterEnabledVersionsCompatibleVersionsReplaceToManyRelationship

	@param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
	@param id the id of the requested resource
	@return ApiGameCenterEnabledVersionsCompatibleVersionsReplaceToManyRelationshipRequest
*/
func (a *GameCenterEnabledVersionsApiService) GameCenterEnabledVersionsCompatibleVersionsReplaceToManyRelationship(ctx context.Context, id string) ApiGameCenterEnabledVersionsCompatibleVersionsReplaceToManyRelationshipRequest {
	return ApiGameCenterEnabledVersionsCompatibleVersionsReplaceToManyRelationshipRequest{
		ApiService: a,
		ctx:        ctx,
		id:         id,
	}
}

// Execute executes the request
func (a *GameCenterEnabledVersionsApiService) GameCenterEnabledVersionsCompatibleVersionsReplaceToManyRelationshipExecute(r ApiGameCenterEnabledVersionsCompatibleVersionsReplaceToManyRelationshipRequest) (*http.Response, error) {
	var (
		localVarHTTPMethod = http.MethodPatch
		localVarPostBody   interface{}
		formFiles          []formFile
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "GameCenterEnabledVersionsApiService.GameCenterEnabledVersionsCompatibleVersionsReplaceToManyRelationship")
	if err != nil {
		return nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/gameCenterEnabledVersions/{id}/relationships/compatibleVersions"
	localVarPath = strings.Replace(localVarPath, "{"+"id"+"}", url.PathEscape(parameterValueToString(r.id, "id")), -1)

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}
	if r.gameCenterEnabledVersionCompatibleVersionsLinkagesRequest == nil {
		return nil, reportError("gameCenterEnabledVersionCompatibleVersionsLinkagesRequest is required and must be specified")
	}

	// to determine the Content-Type header
	localVarHTTPContentTypes := []string{"application/json"}

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
	// body params
	localVarPostBody = r.gameCenterEnabledVersionCompatibleVersionsLinkagesRequest
	req, err := a.client.prepareRequest(r.ctx, localVarPath, localVarHTTPMethod, localVarPostBody, localVarHeaderParams, localVarQueryParams, localVarFormParams, formFiles)
	if err != nil {
		return nil, err
	}

	localVarHTTPResponse, err := a.client.callAPI(req)
	if err != nil || localVarHTTPResponse == nil {
		return localVarHTTPResponse, err
	}

	localVarBody, err := io.ReadAll(localVarHTTPResponse.Body)
	localVarHTTPResponse.Body.Close()
	localVarHTTPResponse.Body = io.NopCloser(bytes.NewBuffer(localVarBody))
	if err != nil {
		return localVarHTTPResponse, err
	}

	if localVarHTTPResponse.StatusCode >= 300 {
		newErr := &GenericOpenAPIError{
			body:  localVarBody,
			error: localVarHTTPResponse.Status,
		}
		if localVarHTTPResponse.StatusCode == 403 {
			var v ErrorResponse
			err = a.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarHTTPResponse, newErr
			}
			newErr.error = formatErrorMessage(localVarHTTPResponse.Status, &v)
			newErr.model = v
			return localVarHTTPResponse, newErr
		}
		if localVarHTTPResponse.StatusCode == 404 {
			var v ErrorResponse
			err = a.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarHTTPResponse, newErr
			}
			newErr.error = formatErrorMessage(localVarHTTPResponse.Status, &v)
			newErr.model = v
			return localVarHTTPResponse, newErr
		}
		if localVarHTTPResponse.StatusCode == 409 {
			var v ErrorResponse
			err = a.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarHTTPResponse, newErr
			}
			newErr.error = formatErrorMessage(localVarHTTPResponse.Status, &v)
			newErr.model = v
			return localVarHTTPResponse, newErr
		}
		return localVarHTTPResponse, newErr
	}

	return localVarHTTPResponse, nil
}
