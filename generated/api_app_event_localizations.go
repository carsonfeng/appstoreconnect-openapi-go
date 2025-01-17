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

// AppEventLocalizationsApiService AppEventLocalizationsApi service
type AppEventLocalizationsApiService service

type ApiAppEventLocalizationsAppEventScreenshotsGetToManyRelatedRequest struct {
	ctx                         context.Context
	ApiService                  *AppEventLocalizationsApiService
	id                          string
	fieldsAppEventScreenshots   *[]string
	fieldsAppEventLocalizations *[]string
	limit                       *int32
	include                     *[]string
}

// the fields to include for returned resources of type appEventScreenshots
func (r ApiAppEventLocalizationsAppEventScreenshotsGetToManyRelatedRequest) FieldsAppEventScreenshots(fieldsAppEventScreenshots []string) ApiAppEventLocalizationsAppEventScreenshotsGetToManyRelatedRequest {
	r.fieldsAppEventScreenshots = &fieldsAppEventScreenshots
	return r
}

// the fields to include for returned resources of type appEventLocalizations
func (r ApiAppEventLocalizationsAppEventScreenshotsGetToManyRelatedRequest) FieldsAppEventLocalizations(fieldsAppEventLocalizations []string) ApiAppEventLocalizationsAppEventScreenshotsGetToManyRelatedRequest {
	r.fieldsAppEventLocalizations = &fieldsAppEventLocalizations
	return r
}

// maximum resources per page
func (r ApiAppEventLocalizationsAppEventScreenshotsGetToManyRelatedRequest) Limit(limit int32) ApiAppEventLocalizationsAppEventScreenshotsGetToManyRelatedRequest {
	r.limit = &limit
	return r
}

// comma-separated list of relationships to include
func (r ApiAppEventLocalizationsAppEventScreenshotsGetToManyRelatedRequest) Include(include []string) ApiAppEventLocalizationsAppEventScreenshotsGetToManyRelatedRequest {
	r.include = &include
	return r
}

func (r ApiAppEventLocalizationsAppEventScreenshotsGetToManyRelatedRequest) Execute() (*AppEventScreenshotsResponse, *http.Response, error) {
	return r.ApiService.AppEventLocalizationsAppEventScreenshotsGetToManyRelatedExecute(r)
}

/*
AppEventLocalizationsAppEventScreenshotsGetToManyRelated Method for AppEventLocalizationsAppEventScreenshotsGetToManyRelated

	@param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
	@param id the id of the requested resource
	@return ApiAppEventLocalizationsAppEventScreenshotsGetToManyRelatedRequest
*/
func (a *AppEventLocalizationsApiService) AppEventLocalizationsAppEventScreenshotsGetToManyRelated(ctx context.Context, id string) ApiAppEventLocalizationsAppEventScreenshotsGetToManyRelatedRequest {
	return ApiAppEventLocalizationsAppEventScreenshotsGetToManyRelatedRequest{
		ApiService: a,
		ctx:        ctx,
		id:         id,
	}
}

// Execute executes the request
//
//	@return AppEventScreenshotsResponse
func (a *AppEventLocalizationsApiService) AppEventLocalizationsAppEventScreenshotsGetToManyRelatedExecute(r ApiAppEventLocalizationsAppEventScreenshotsGetToManyRelatedRequest) (*AppEventScreenshotsResponse, *http.Response, error) {
	var (
		localVarHTTPMethod  = http.MethodGet
		localVarPostBody    interface{}
		formFiles           []formFile
		localVarReturnValue *AppEventScreenshotsResponse
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "AppEventLocalizationsApiService.AppEventLocalizationsAppEventScreenshotsGetToManyRelated")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/appEventLocalizations/{id}/appEventScreenshots"
	localVarPath = strings.Replace(localVarPath, "{"+"id"+"}", url.PathEscape(parameterValueToString(r.id, "id")), -1)

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}

	if r.fieldsAppEventScreenshots != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "fields[appEventScreenshots]", r.fieldsAppEventScreenshots, "csv")
	}
	if r.fieldsAppEventLocalizations != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "fields[appEventLocalizations]", r.fieldsAppEventLocalizations, "csv")
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

type ApiAppEventLocalizationsAppEventVideoClipsGetToManyRelatedRequest struct {
	ctx                         context.Context
	ApiService                  *AppEventLocalizationsApiService
	id                          string
	fieldsAppEventVideoClips    *[]string
	fieldsAppEventLocalizations *[]string
	limit                       *int32
	include                     *[]string
}

// the fields to include for returned resources of type appEventVideoClips
func (r ApiAppEventLocalizationsAppEventVideoClipsGetToManyRelatedRequest) FieldsAppEventVideoClips(fieldsAppEventVideoClips []string) ApiAppEventLocalizationsAppEventVideoClipsGetToManyRelatedRequest {
	r.fieldsAppEventVideoClips = &fieldsAppEventVideoClips
	return r
}

// the fields to include for returned resources of type appEventLocalizations
func (r ApiAppEventLocalizationsAppEventVideoClipsGetToManyRelatedRequest) FieldsAppEventLocalizations(fieldsAppEventLocalizations []string) ApiAppEventLocalizationsAppEventVideoClipsGetToManyRelatedRequest {
	r.fieldsAppEventLocalizations = &fieldsAppEventLocalizations
	return r
}

// maximum resources per page
func (r ApiAppEventLocalizationsAppEventVideoClipsGetToManyRelatedRequest) Limit(limit int32) ApiAppEventLocalizationsAppEventVideoClipsGetToManyRelatedRequest {
	r.limit = &limit
	return r
}

// comma-separated list of relationships to include
func (r ApiAppEventLocalizationsAppEventVideoClipsGetToManyRelatedRequest) Include(include []string) ApiAppEventLocalizationsAppEventVideoClipsGetToManyRelatedRequest {
	r.include = &include
	return r
}

func (r ApiAppEventLocalizationsAppEventVideoClipsGetToManyRelatedRequest) Execute() (*AppEventVideoClipsResponse, *http.Response, error) {
	return r.ApiService.AppEventLocalizationsAppEventVideoClipsGetToManyRelatedExecute(r)
}

/*
AppEventLocalizationsAppEventVideoClipsGetToManyRelated Method for AppEventLocalizationsAppEventVideoClipsGetToManyRelated

	@param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
	@param id the id of the requested resource
	@return ApiAppEventLocalizationsAppEventVideoClipsGetToManyRelatedRequest
*/
func (a *AppEventLocalizationsApiService) AppEventLocalizationsAppEventVideoClipsGetToManyRelated(ctx context.Context, id string) ApiAppEventLocalizationsAppEventVideoClipsGetToManyRelatedRequest {
	return ApiAppEventLocalizationsAppEventVideoClipsGetToManyRelatedRequest{
		ApiService: a,
		ctx:        ctx,
		id:         id,
	}
}

// Execute executes the request
//
//	@return AppEventVideoClipsResponse
func (a *AppEventLocalizationsApiService) AppEventLocalizationsAppEventVideoClipsGetToManyRelatedExecute(r ApiAppEventLocalizationsAppEventVideoClipsGetToManyRelatedRequest) (*AppEventVideoClipsResponse, *http.Response, error) {
	var (
		localVarHTTPMethod  = http.MethodGet
		localVarPostBody    interface{}
		formFiles           []formFile
		localVarReturnValue *AppEventVideoClipsResponse
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "AppEventLocalizationsApiService.AppEventLocalizationsAppEventVideoClipsGetToManyRelated")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/appEventLocalizations/{id}/appEventVideoClips"
	localVarPath = strings.Replace(localVarPath, "{"+"id"+"}", url.PathEscape(parameterValueToString(r.id, "id")), -1)

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}

	if r.fieldsAppEventVideoClips != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "fields[appEventVideoClips]", r.fieldsAppEventVideoClips, "csv")
	}
	if r.fieldsAppEventLocalizations != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "fields[appEventLocalizations]", r.fieldsAppEventLocalizations, "csv")
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

type ApiAppEventLocalizationsCreateInstanceRequest struct {
	ctx                               context.Context
	ApiService                        *AppEventLocalizationsApiService
	appEventLocalizationCreateRequest *AppEventLocalizationCreateRequest
}

// AppEventLocalization representation
func (r ApiAppEventLocalizationsCreateInstanceRequest) AppEventLocalizationCreateRequest(appEventLocalizationCreateRequest AppEventLocalizationCreateRequest) ApiAppEventLocalizationsCreateInstanceRequest {
	r.appEventLocalizationCreateRequest = &appEventLocalizationCreateRequest
	return r
}

func (r ApiAppEventLocalizationsCreateInstanceRequest) Execute() (*AppEventLocalizationResponse, *http.Response, error) {
	return r.ApiService.AppEventLocalizationsCreateInstanceExecute(r)
}

/*
AppEventLocalizationsCreateInstance Method for AppEventLocalizationsCreateInstance

	@param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
	@return ApiAppEventLocalizationsCreateInstanceRequest
*/
func (a *AppEventLocalizationsApiService) AppEventLocalizationsCreateInstance(ctx context.Context) ApiAppEventLocalizationsCreateInstanceRequest {
	return ApiAppEventLocalizationsCreateInstanceRequest{
		ApiService: a,
		ctx:        ctx,
	}
}

// Execute executes the request
//
//	@return AppEventLocalizationResponse
func (a *AppEventLocalizationsApiService) AppEventLocalizationsCreateInstanceExecute(r ApiAppEventLocalizationsCreateInstanceRequest) (*AppEventLocalizationResponse, *http.Response, error) {
	var (
		localVarHTTPMethod  = http.MethodPost
		localVarPostBody    interface{}
		formFiles           []formFile
		localVarReturnValue *AppEventLocalizationResponse
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "AppEventLocalizationsApiService.AppEventLocalizationsCreateInstance")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/appEventLocalizations"

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}
	if r.appEventLocalizationCreateRequest == nil {
		return localVarReturnValue, nil, reportError("appEventLocalizationCreateRequest is required and must be specified")
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
	localVarPostBody = r.appEventLocalizationCreateRequest
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
		if localVarHTTPResponse.StatusCode == 409 {
			var v ErrorResponse
			err = a.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarReturnValue, localVarHTTPResponse, newErr
			}
			newErr.error = formatErrorMessage(localVarHTTPResponse.Status, &v)
			newErr.model = v
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

type ApiAppEventLocalizationsDeleteInstanceRequest struct {
	ctx        context.Context
	ApiService *AppEventLocalizationsApiService
	id         string
}

func (r ApiAppEventLocalizationsDeleteInstanceRequest) Execute() (*http.Response, error) {
	return r.ApiService.AppEventLocalizationsDeleteInstanceExecute(r)
}

/*
AppEventLocalizationsDeleteInstance Method for AppEventLocalizationsDeleteInstance

	@param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
	@param id the id of the requested resource
	@return ApiAppEventLocalizationsDeleteInstanceRequest
*/
func (a *AppEventLocalizationsApiService) AppEventLocalizationsDeleteInstance(ctx context.Context, id string) ApiAppEventLocalizationsDeleteInstanceRequest {
	return ApiAppEventLocalizationsDeleteInstanceRequest{
		ApiService: a,
		ctx:        ctx,
		id:         id,
	}
}

// Execute executes the request
func (a *AppEventLocalizationsApiService) AppEventLocalizationsDeleteInstanceExecute(r ApiAppEventLocalizationsDeleteInstanceRequest) (*http.Response, error) {
	var (
		localVarHTTPMethod = http.MethodDelete
		localVarPostBody   interface{}
		formFiles          []formFile
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "AppEventLocalizationsApiService.AppEventLocalizationsDeleteInstance")
	if err != nil {
		return nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/appEventLocalizations/{id}"
	localVarPath = strings.Replace(localVarPath, "{"+"id"+"}", url.PathEscape(parameterValueToString(r.id, "id")), -1)

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}

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
		if localVarHTTPResponse.StatusCode == 400 {
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

type ApiAppEventLocalizationsGetInstanceRequest struct {
	ctx                         context.Context
	ApiService                  *AppEventLocalizationsApiService
	id                          string
	fieldsAppEventLocalizations *[]string
	include                     *[]string
	fieldsAppEventScreenshots   *[]string
	fieldsAppEventVideoClips    *[]string
	limitAppEventScreenshots    *int32
	limitAppEventVideoClips     *int32
}

// the fields to include for returned resources of type appEventLocalizations
func (r ApiAppEventLocalizationsGetInstanceRequest) FieldsAppEventLocalizations(fieldsAppEventLocalizations []string) ApiAppEventLocalizationsGetInstanceRequest {
	r.fieldsAppEventLocalizations = &fieldsAppEventLocalizations
	return r
}

// comma-separated list of relationships to include
func (r ApiAppEventLocalizationsGetInstanceRequest) Include(include []string) ApiAppEventLocalizationsGetInstanceRequest {
	r.include = &include
	return r
}

// the fields to include for returned resources of type appEventScreenshots
func (r ApiAppEventLocalizationsGetInstanceRequest) FieldsAppEventScreenshots(fieldsAppEventScreenshots []string) ApiAppEventLocalizationsGetInstanceRequest {
	r.fieldsAppEventScreenshots = &fieldsAppEventScreenshots
	return r
}

// the fields to include for returned resources of type appEventVideoClips
func (r ApiAppEventLocalizationsGetInstanceRequest) FieldsAppEventVideoClips(fieldsAppEventVideoClips []string) ApiAppEventLocalizationsGetInstanceRequest {
	r.fieldsAppEventVideoClips = &fieldsAppEventVideoClips
	return r
}

// maximum number of related appEventScreenshots returned (when they are included)
func (r ApiAppEventLocalizationsGetInstanceRequest) LimitAppEventScreenshots(limitAppEventScreenshots int32) ApiAppEventLocalizationsGetInstanceRequest {
	r.limitAppEventScreenshots = &limitAppEventScreenshots
	return r
}

// maximum number of related appEventVideoClips returned (when they are included)
func (r ApiAppEventLocalizationsGetInstanceRequest) LimitAppEventVideoClips(limitAppEventVideoClips int32) ApiAppEventLocalizationsGetInstanceRequest {
	r.limitAppEventVideoClips = &limitAppEventVideoClips
	return r
}

func (r ApiAppEventLocalizationsGetInstanceRequest) Execute() (*AppEventLocalizationResponse, *http.Response, error) {
	return r.ApiService.AppEventLocalizationsGetInstanceExecute(r)
}

/*
AppEventLocalizationsGetInstance Method for AppEventLocalizationsGetInstance

	@param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
	@param id the id of the requested resource
	@return ApiAppEventLocalizationsGetInstanceRequest
*/
func (a *AppEventLocalizationsApiService) AppEventLocalizationsGetInstance(ctx context.Context, id string) ApiAppEventLocalizationsGetInstanceRequest {
	return ApiAppEventLocalizationsGetInstanceRequest{
		ApiService: a,
		ctx:        ctx,
		id:         id,
	}
}

// Execute executes the request
//
//	@return AppEventLocalizationResponse
func (a *AppEventLocalizationsApiService) AppEventLocalizationsGetInstanceExecute(r ApiAppEventLocalizationsGetInstanceRequest) (*AppEventLocalizationResponse, *http.Response, error) {
	var (
		localVarHTTPMethod  = http.MethodGet
		localVarPostBody    interface{}
		formFiles           []formFile
		localVarReturnValue *AppEventLocalizationResponse
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "AppEventLocalizationsApiService.AppEventLocalizationsGetInstance")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/appEventLocalizations/{id}"
	localVarPath = strings.Replace(localVarPath, "{"+"id"+"}", url.PathEscape(parameterValueToString(r.id, "id")), -1)

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}

	if r.fieldsAppEventLocalizations != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "fields[appEventLocalizations]", r.fieldsAppEventLocalizations, "csv")
	}
	if r.include != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "include", r.include, "csv")
	}
	if r.fieldsAppEventScreenshots != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "fields[appEventScreenshots]", r.fieldsAppEventScreenshots, "csv")
	}
	if r.fieldsAppEventVideoClips != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "fields[appEventVideoClips]", r.fieldsAppEventVideoClips, "csv")
	}
	if r.limitAppEventScreenshots != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "limit[appEventScreenshots]", r.limitAppEventScreenshots, "")
	}
	if r.limitAppEventVideoClips != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "limit[appEventVideoClips]", r.limitAppEventVideoClips, "")
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

type ApiAppEventLocalizationsUpdateInstanceRequest struct {
	ctx                               context.Context
	ApiService                        *AppEventLocalizationsApiService
	id                                string
	appEventLocalizationUpdateRequest *AppEventLocalizationUpdateRequest
}

// AppEventLocalization representation
func (r ApiAppEventLocalizationsUpdateInstanceRequest) AppEventLocalizationUpdateRequest(appEventLocalizationUpdateRequest AppEventLocalizationUpdateRequest) ApiAppEventLocalizationsUpdateInstanceRequest {
	r.appEventLocalizationUpdateRequest = &appEventLocalizationUpdateRequest
	return r
}

func (r ApiAppEventLocalizationsUpdateInstanceRequest) Execute() (*AppEventLocalizationResponse, *http.Response, error) {
	return r.ApiService.AppEventLocalizationsUpdateInstanceExecute(r)
}

/*
AppEventLocalizationsUpdateInstance Method for AppEventLocalizationsUpdateInstance

	@param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
	@param id the id of the requested resource
	@return ApiAppEventLocalizationsUpdateInstanceRequest
*/
func (a *AppEventLocalizationsApiService) AppEventLocalizationsUpdateInstance(ctx context.Context, id string) ApiAppEventLocalizationsUpdateInstanceRequest {
	return ApiAppEventLocalizationsUpdateInstanceRequest{
		ApiService: a,
		ctx:        ctx,
		id:         id,
	}
}

// Execute executes the request
//
//	@return AppEventLocalizationResponse
func (a *AppEventLocalizationsApiService) AppEventLocalizationsUpdateInstanceExecute(r ApiAppEventLocalizationsUpdateInstanceRequest) (*AppEventLocalizationResponse, *http.Response, error) {
	var (
		localVarHTTPMethod  = http.MethodPatch
		localVarPostBody    interface{}
		formFiles           []formFile
		localVarReturnValue *AppEventLocalizationResponse
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "AppEventLocalizationsApiService.AppEventLocalizationsUpdateInstance")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/appEventLocalizations/{id}"
	localVarPath = strings.Replace(localVarPath, "{"+"id"+"}", url.PathEscape(parameterValueToString(r.id, "id")), -1)

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}
	if r.appEventLocalizationUpdateRequest == nil {
		return localVarReturnValue, nil, reportError("appEventLocalizationUpdateRequest is required and must be specified")
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
	localVarPostBody = r.appEventLocalizationUpdateRequest
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
		if localVarHTTPResponse.StatusCode == 409 {
			var v ErrorResponse
			err = a.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarReturnValue, localVarHTTPResponse, newErr
			}
			newErr.error = formatErrorMessage(localVarHTTPResponse.Status, &v)
			newErr.model = v
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
