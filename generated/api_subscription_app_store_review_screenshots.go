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

// SubscriptionAppStoreReviewScreenshotsApiService SubscriptionAppStoreReviewScreenshotsApi service
type SubscriptionAppStoreReviewScreenshotsApiService service

type ApiSubscriptionAppStoreReviewScreenshotsCreateInstanceRequest struct {
	ctx                                               context.Context
	ApiService                                        *SubscriptionAppStoreReviewScreenshotsApiService
	subscriptionAppStoreReviewScreenshotCreateRequest *SubscriptionAppStoreReviewScreenshotCreateRequest
}

// SubscriptionAppStoreReviewScreenshot representation
func (r ApiSubscriptionAppStoreReviewScreenshotsCreateInstanceRequest) SubscriptionAppStoreReviewScreenshotCreateRequest(subscriptionAppStoreReviewScreenshotCreateRequest SubscriptionAppStoreReviewScreenshotCreateRequest) ApiSubscriptionAppStoreReviewScreenshotsCreateInstanceRequest {
	r.subscriptionAppStoreReviewScreenshotCreateRequest = &subscriptionAppStoreReviewScreenshotCreateRequest
	return r
}

func (r ApiSubscriptionAppStoreReviewScreenshotsCreateInstanceRequest) Execute() (*SubscriptionAppStoreReviewScreenshotResponse, *http.Response, error) {
	return r.ApiService.SubscriptionAppStoreReviewScreenshotsCreateInstanceExecute(r)
}

/*
SubscriptionAppStoreReviewScreenshotsCreateInstance Method for SubscriptionAppStoreReviewScreenshotsCreateInstance

	@param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
	@return ApiSubscriptionAppStoreReviewScreenshotsCreateInstanceRequest
*/
func (a *SubscriptionAppStoreReviewScreenshotsApiService) SubscriptionAppStoreReviewScreenshotsCreateInstance(ctx context.Context) ApiSubscriptionAppStoreReviewScreenshotsCreateInstanceRequest {
	return ApiSubscriptionAppStoreReviewScreenshotsCreateInstanceRequest{
		ApiService: a,
		ctx:        ctx,
	}
}

// Execute executes the request
//
//	@return SubscriptionAppStoreReviewScreenshotResponse
func (a *SubscriptionAppStoreReviewScreenshotsApiService) SubscriptionAppStoreReviewScreenshotsCreateInstanceExecute(r ApiSubscriptionAppStoreReviewScreenshotsCreateInstanceRequest) (*SubscriptionAppStoreReviewScreenshotResponse, *http.Response, error) {
	var (
		localVarHTTPMethod  = http.MethodPost
		localVarPostBody    interface{}
		formFiles           []formFile
		localVarReturnValue *SubscriptionAppStoreReviewScreenshotResponse
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "SubscriptionAppStoreReviewScreenshotsApiService.SubscriptionAppStoreReviewScreenshotsCreateInstance")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/subscriptionAppStoreReviewScreenshots"

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}
	if r.subscriptionAppStoreReviewScreenshotCreateRequest == nil {
		return localVarReturnValue, nil, reportError("subscriptionAppStoreReviewScreenshotCreateRequest is required and must be specified")
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
	localVarPostBody = r.subscriptionAppStoreReviewScreenshotCreateRequest
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

type ApiSubscriptionAppStoreReviewScreenshotsDeleteInstanceRequest struct {
	ctx        context.Context
	ApiService *SubscriptionAppStoreReviewScreenshotsApiService
	id         string
}

func (r ApiSubscriptionAppStoreReviewScreenshotsDeleteInstanceRequest) Execute() (*http.Response, error) {
	return r.ApiService.SubscriptionAppStoreReviewScreenshotsDeleteInstanceExecute(r)
}

/*
SubscriptionAppStoreReviewScreenshotsDeleteInstance Method for SubscriptionAppStoreReviewScreenshotsDeleteInstance

	@param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
	@param id the id of the requested resource
	@return ApiSubscriptionAppStoreReviewScreenshotsDeleteInstanceRequest
*/
func (a *SubscriptionAppStoreReviewScreenshotsApiService) SubscriptionAppStoreReviewScreenshotsDeleteInstance(ctx context.Context, id string) ApiSubscriptionAppStoreReviewScreenshotsDeleteInstanceRequest {
	return ApiSubscriptionAppStoreReviewScreenshotsDeleteInstanceRequest{
		ApiService: a,
		ctx:        ctx,
		id:         id,
	}
}

// Execute executes the request
func (a *SubscriptionAppStoreReviewScreenshotsApiService) SubscriptionAppStoreReviewScreenshotsDeleteInstanceExecute(r ApiSubscriptionAppStoreReviewScreenshotsDeleteInstanceRequest) (*http.Response, error) {
	var (
		localVarHTTPMethod = http.MethodDelete
		localVarPostBody   interface{}
		formFiles          []formFile
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "SubscriptionAppStoreReviewScreenshotsApiService.SubscriptionAppStoreReviewScreenshotsDeleteInstance")
	if err != nil {
		return nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/subscriptionAppStoreReviewScreenshots/{id}"
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

type ApiSubscriptionAppStoreReviewScreenshotsGetInstanceRequest struct {
	ctx                                         context.Context
	ApiService                                  *SubscriptionAppStoreReviewScreenshotsApiService
	id                                          string
	fieldsSubscriptionAppStoreReviewScreenshots *[]string
	include                                     *[]string
}

// the fields to include for returned resources of type subscriptionAppStoreReviewScreenshots
func (r ApiSubscriptionAppStoreReviewScreenshotsGetInstanceRequest) FieldsSubscriptionAppStoreReviewScreenshots(fieldsSubscriptionAppStoreReviewScreenshots []string) ApiSubscriptionAppStoreReviewScreenshotsGetInstanceRequest {
	r.fieldsSubscriptionAppStoreReviewScreenshots = &fieldsSubscriptionAppStoreReviewScreenshots
	return r
}

// comma-separated list of relationships to include
func (r ApiSubscriptionAppStoreReviewScreenshotsGetInstanceRequest) Include(include []string) ApiSubscriptionAppStoreReviewScreenshotsGetInstanceRequest {
	r.include = &include
	return r
}

func (r ApiSubscriptionAppStoreReviewScreenshotsGetInstanceRequest) Execute() (*SubscriptionAppStoreReviewScreenshotResponse, *http.Response, error) {
	return r.ApiService.SubscriptionAppStoreReviewScreenshotsGetInstanceExecute(r)
}

/*
SubscriptionAppStoreReviewScreenshotsGetInstance Method for SubscriptionAppStoreReviewScreenshotsGetInstance

	@param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
	@param id the id of the requested resource
	@return ApiSubscriptionAppStoreReviewScreenshotsGetInstanceRequest
*/
func (a *SubscriptionAppStoreReviewScreenshotsApiService) SubscriptionAppStoreReviewScreenshotsGetInstance(ctx context.Context, id string) ApiSubscriptionAppStoreReviewScreenshotsGetInstanceRequest {
	return ApiSubscriptionAppStoreReviewScreenshotsGetInstanceRequest{
		ApiService: a,
		ctx:        ctx,
		id:         id,
	}
}

// Execute executes the request
//
//	@return SubscriptionAppStoreReviewScreenshotResponse
func (a *SubscriptionAppStoreReviewScreenshotsApiService) SubscriptionAppStoreReviewScreenshotsGetInstanceExecute(r ApiSubscriptionAppStoreReviewScreenshotsGetInstanceRequest) (*SubscriptionAppStoreReviewScreenshotResponse, *http.Response, error) {
	var (
		localVarHTTPMethod  = http.MethodGet
		localVarPostBody    interface{}
		formFiles           []formFile
		localVarReturnValue *SubscriptionAppStoreReviewScreenshotResponse
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "SubscriptionAppStoreReviewScreenshotsApiService.SubscriptionAppStoreReviewScreenshotsGetInstance")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/subscriptionAppStoreReviewScreenshots/{id}"
	localVarPath = strings.Replace(localVarPath, "{"+"id"+"}", url.PathEscape(parameterValueToString(r.id, "id")), -1)

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}

	if r.fieldsSubscriptionAppStoreReviewScreenshots != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "fields[subscriptionAppStoreReviewScreenshots]", r.fieldsSubscriptionAppStoreReviewScreenshots, "csv")
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

type ApiSubscriptionAppStoreReviewScreenshotsUpdateInstanceRequest struct {
	ctx                                               context.Context
	ApiService                                        *SubscriptionAppStoreReviewScreenshotsApiService
	id                                                string
	subscriptionAppStoreReviewScreenshotUpdateRequest *SubscriptionAppStoreReviewScreenshotUpdateRequest
}

// SubscriptionAppStoreReviewScreenshot representation
func (r ApiSubscriptionAppStoreReviewScreenshotsUpdateInstanceRequest) SubscriptionAppStoreReviewScreenshotUpdateRequest(subscriptionAppStoreReviewScreenshotUpdateRequest SubscriptionAppStoreReviewScreenshotUpdateRequest) ApiSubscriptionAppStoreReviewScreenshotsUpdateInstanceRequest {
	r.subscriptionAppStoreReviewScreenshotUpdateRequest = &subscriptionAppStoreReviewScreenshotUpdateRequest
	return r
}

func (r ApiSubscriptionAppStoreReviewScreenshotsUpdateInstanceRequest) Execute() (*SubscriptionAppStoreReviewScreenshotResponse, *http.Response, error) {
	return r.ApiService.SubscriptionAppStoreReviewScreenshotsUpdateInstanceExecute(r)
}

/*
SubscriptionAppStoreReviewScreenshotsUpdateInstance Method for SubscriptionAppStoreReviewScreenshotsUpdateInstance

	@param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
	@param id the id of the requested resource
	@return ApiSubscriptionAppStoreReviewScreenshotsUpdateInstanceRequest
*/
func (a *SubscriptionAppStoreReviewScreenshotsApiService) SubscriptionAppStoreReviewScreenshotsUpdateInstance(ctx context.Context, id string) ApiSubscriptionAppStoreReviewScreenshotsUpdateInstanceRequest {
	return ApiSubscriptionAppStoreReviewScreenshotsUpdateInstanceRequest{
		ApiService: a,
		ctx:        ctx,
		id:         id,
	}
}

// Execute executes the request
//
//	@return SubscriptionAppStoreReviewScreenshotResponse
func (a *SubscriptionAppStoreReviewScreenshotsApiService) SubscriptionAppStoreReviewScreenshotsUpdateInstanceExecute(r ApiSubscriptionAppStoreReviewScreenshotsUpdateInstanceRequest) (*SubscriptionAppStoreReviewScreenshotResponse, *http.Response, error) {
	var (
		localVarHTTPMethod  = http.MethodPatch
		localVarPostBody    interface{}
		formFiles           []formFile
		localVarReturnValue *SubscriptionAppStoreReviewScreenshotResponse
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "SubscriptionAppStoreReviewScreenshotsApiService.SubscriptionAppStoreReviewScreenshotsUpdateInstance")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/subscriptionAppStoreReviewScreenshots/{id}"
	localVarPath = strings.Replace(localVarPath, "{"+"id"+"}", url.PathEscape(parameterValueToString(r.id, "id")), -1)

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}
	if r.subscriptionAppStoreReviewScreenshotUpdateRequest == nil {
		return localVarReturnValue, nil, reportError("subscriptionAppStoreReviewScreenshotUpdateRequest is required and must be specified")
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
	localVarPostBody = r.subscriptionAppStoreReviewScreenshotUpdateRequest
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
