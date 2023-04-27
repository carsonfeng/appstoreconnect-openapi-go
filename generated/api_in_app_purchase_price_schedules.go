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

// InAppPurchasePriceSchedulesApiService InAppPurchasePriceSchedulesApi service
type InAppPurchasePriceSchedulesApiService service

type ApiInAppPurchasePriceSchedulesAutomaticPricesGetToManyRelatedRequest struct {
	ctx                            context.Context
	ApiService                     *InAppPurchasePriceSchedulesApiService
	id                             string
	filterTerritory                *[]string
	fieldsInAppPurchasePricePoints *[]string
	fieldsInAppPurchasePrices      *[]string
	fieldsTerritories              *[]string
	limit                          *int32
	include                        *[]string
}

// filter by id(s) of related &#39;territory&#39;
func (r ApiInAppPurchasePriceSchedulesAutomaticPricesGetToManyRelatedRequest) FilterTerritory(filterTerritory []string) ApiInAppPurchasePriceSchedulesAutomaticPricesGetToManyRelatedRequest {
	r.filterTerritory = &filterTerritory
	return r
}

// the fields to include for returned resources of type inAppPurchasePricePoints
func (r ApiInAppPurchasePriceSchedulesAutomaticPricesGetToManyRelatedRequest) FieldsInAppPurchasePricePoints(fieldsInAppPurchasePricePoints []string) ApiInAppPurchasePriceSchedulesAutomaticPricesGetToManyRelatedRequest {
	r.fieldsInAppPurchasePricePoints = &fieldsInAppPurchasePricePoints
	return r
}

// the fields to include for returned resources of type inAppPurchasePrices
func (r ApiInAppPurchasePriceSchedulesAutomaticPricesGetToManyRelatedRequest) FieldsInAppPurchasePrices(fieldsInAppPurchasePrices []string) ApiInAppPurchasePriceSchedulesAutomaticPricesGetToManyRelatedRequest {
	r.fieldsInAppPurchasePrices = &fieldsInAppPurchasePrices
	return r
}

// the fields to include for returned resources of type territories
func (r ApiInAppPurchasePriceSchedulesAutomaticPricesGetToManyRelatedRequest) FieldsTerritories(fieldsTerritories []string) ApiInAppPurchasePriceSchedulesAutomaticPricesGetToManyRelatedRequest {
	r.fieldsTerritories = &fieldsTerritories
	return r
}

// maximum resources per page
func (r ApiInAppPurchasePriceSchedulesAutomaticPricesGetToManyRelatedRequest) Limit(limit int32) ApiInAppPurchasePriceSchedulesAutomaticPricesGetToManyRelatedRequest {
	r.limit = &limit
	return r
}

// comma-separated list of relationships to include
func (r ApiInAppPurchasePriceSchedulesAutomaticPricesGetToManyRelatedRequest) Include(include []string) ApiInAppPurchasePriceSchedulesAutomaticPricesGetToManyRelatedRequest {
	r.include = &include
	return r
}

func (r ApiInAppPurchasePriceSchedulesAutomaticPricesGetToManyRelatedRequest) Execute() (*InAppPurchasePricesResponse, *http.Response, error) {
	return r.ApiService.InAppPurchasePriceSchedulesAutomaticPricesGetToManyRelatedExecute(r)
}

/*
InAppPurchasePriceSchedulesAutomaticPricesGetToManyRelated Method for InAppPurchasePriceSchedulesAutomaticPricesGetToManyRelated

	@param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
	@param id the id of the requested resource
	@return ApiInAppPurchasePriceSchedulesAutomaticPricesGetToManyRelatedRequest
*/
func (a *InAppPurchasePriceSchedulesApiService) InAppPurchasePriceSchedulesAutomaticPricesGetToManyRelated(ctx context.Context, id string) ApiInAppPurchasePriceSchedulesAutomaticPricesGetToManyRelatedRequest {
	return ApiInAppPurchasePriceSchedulesAutomaticPricesGetToManyRelatedRequest{
		ApiService: a,
		ctx:        ctx,
		id:         id,
	}
}

// Execute executes the request
//
//	@return InAppPurchasePricesResponse
func (a *InAppPurchasePriceSchedulesApiService) InAppPurchasePriceSchedulesAutomaticPricesGetToManyRelatedExecute(r ApiInAppPurchasePriceSchedulesAutomaticPricesGetToManyRelatedRequest) (*InAppPurchasePricesResponse, *http.Response, error) {
	var (
		localVarHTTPMethod  = http.MethodGet
		localVarPostBody    interface{}
		formFiles           []formFile
		localVarReturnValue *InAppPurchasePricesResponse
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "InAppPurchasePriceSchedulesApiService.InAppPurchasePriceSchedulesAutomaticPricesGetToManyRelated")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/inAppPurchasePriceSchedules/{id}/automaticPrices"
	localVarPath = strings.Replace(localVarPath, "{"+"id"+"}", url.PathEscape(parameterValueToString(r.id, "id")), -1)

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}

	if r.filterTerritory != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "filter[territory]", r.filterTerritory, "csv")
	}
	if r.fieldsInAppPurchasePricePoints != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "fields[inAppPurchasePricePoints]", r.fieldsInAppPurchasePricePoints, "csv")
	}
	if r.fieldsInAppPurchasePrices != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "fields[inAppPurchasePrices]", r.fieldsInAppPurchasePrices, "csv")
	}
	if r.fieldsTerritories != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "fields[territories]", r.fieldsTerritories, "csv")
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

type ApiInAppPurchasePriceSchedulesBaseTerritoryGetToOneRelatedRequest struct {
	ctx               context.Context
	ApiService        *InAppPurchasePriceSchedulesApiService
	id                string
	fieldsTerritories *[]string
}

// the fields to include for returned resources of type territories
func (r ApiInAppPurchasePriceSchedulesBaseTerritoryGetToOneRelatedRequest) FieldsTerritories(fieldsTerritories []string) ApiInAppPurchasePriceSchedulesBaseTerritoryGetToOneRelatedRequest {
	r.fieldsTerritories = &fieldsTerritories
	return r
}

func (r ApiInAppPurchasePriceSchedulesBaseTerritoryGetToOneRelatedRequest) Execute() (*TerritoryResponse, *http.Response, error) {
	return r.ApiService.InAppPurchasePriceSchedulesBaseTerritoryGetToOneRelatedExecute(r)
}

/*
InAppPurchasePriceSchedulesBaseTerritoryGetToOneRelated Method for InAppPurchasePriceSchedulesBaseTerritoryGetToOneRelated

	@param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
	@param id the id of the requested resource
	@return ApiInAppPurchasePriceSchedulesBaseTerritoryGetToOneRelatedRequest
*/
func (a *InAppPurchasePriceSchedulesApiService) InAppPurchasePriceSchedulesBaseTerritoryGetToOneRelated(ctx context.Context, id string) ApiInAppPurchasePriceSchedulesBaseTerritoryGetToOneRelatedRequest {
	return ApiInAppPurchasePriceSchedulesBaseTerritoryGetToOneRelatedRequest{
		ApiService: a,
		ctx:        ctx,
		id:         id,
	}
}

// Execute executes the request
//
//	@return TerritoryResponse
func (a *InAppPurchasePriceSchedulesApiService) InAppPurchasePriceSchedulesBaseTerritoryGetToOneRelatedExecute(r ApiInAppPurchasePriceSchedulesBaseTerritoryGetToOneRelatedRequest) (*TerritoryResponse, *http.Response, error) {
	var (
		localVarHTTPMethod  = http.MethodGet
		localVarPostBody    interface{}
		formFiles           []formFile
		localVarReturnValue *TerritoryResponse
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "InAppPurchasePriceSchedulesApiService.InAppPurchasePriceSchedulesBaseTerritoryGetToOneRelated")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/inAppPurchasePriceSchedules/{id}/baseTerritory"
	localVarPath = strings.Replace(localVarPath, "{"+"id"+"}", url.PathEscape(parameterValueToString(r.id, "id")), -1)

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}

	if r.fieldsTerritories != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "fields[territories]", r.fieldsTerritories, "csv")
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

type ApiInAppPurchasePriceSchedulesCreateInstanceRequest struct {
	ctx                                     context.Context
	ApiService                              *InAppPurchasePriceSchedulesApiService
	inAppPurchasePriceScheduleCreateRequest *InAppPurchasePriceScheduleCreateRequest
}

// InAppPurchasePriceSchedule representation
func (r ApiInAppPurchasePriceSchedulesCreateInstanceRequest) InAppPurchasePriceScheduleCreateRequest(inAppPurchasePriceScheduleCreateRequest InAppPurchasePriceScheduleCreateRequest) ApiInAppPurchasePriceSchedulesCreateInstanceRequest {
	r.inAppPurchasePriceScheduleCreateRequest = &inAppPurchasePriceScheduleCreateRequest
	return r
}

func (r ApiInAppPurchasePriceSchedulesCreateInstanceRequest) Execute() (*InAppPurchasePriceScheduleResponse, *http.Response, error) {
	return r.ApiService.InAppPurchasePriceSchedulesCreateInstanceExecute(r)
}

/*
InAppPurchasePriceSchedulesCreateInstance Method for InAppPurchasePriceSchedulesCreateInstance

	@param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
	@return ApiInAppPurchasePriceSchedulesCreateInstanceRequest
*/
func (a *InAppPurchasePriceSchedulesApiService) InAppPurchasePriceSchedulesCreateInstance(ctx context.Context) ApiInAppPurchasePriceSchedulesCreateInstanceRequest {
	return ApiInAppPurchasePriceSchedulesCreateInstanceRequest{
		ApiService: a,
		ctx:        ctx,
	}
}

// Execute executes the request
//
//	@return InAppPurchasePriceScheduleResponse
func (a *InAppPurchasePriceSchedulesApiService) InAppPurchasePriceSchedulesCreateInstanceExecute(r ApiInAppPurchasePriceSchedulesCreateInstanceRequest) (*InAppPurchasePriceScheduleResponse, *http.Response, error) {
	var (
		localVarHTTPMethod  = http.MethodPost
		localVarPostBody    interface{}
		formFiles           []formFile
		localVarReturnValue *InAppPurchasePriceScheduleResponse
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "InAppPurchasePriceSchedulesApiService.InAppPurchasePriceSchedulesCreateInstance")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/inAppPurchasePriceSchedules"

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}
	if r.inAppPurchasePriceScheduleCreateRequest == nil {
		return localVarReturnValue, nil, reportError("inAppPurchasePriceScheduleCreateRequest is required and must be specified")
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
	localVarPostBody = r.inAppPurchasePriceScheduleCreateRequest
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

type ApiInAppPurchasePriceSchedulesGetInstanceRequest struct {
	ctx                               context.Context
	ApiService                        *InAppPurchasePriceSchedulesApiService
	id                                string
	fieldsInAppPurchasePriceSchedules *[]string
	include                           *[]string
	fieldsInAppPurchasePrices         *[]string
	fieldsTerritories                 *[]string
	limitAutomaticPrices              *int32
	limitManualPrices                 *int32
}

// the fields to include for returned resources of type inAppPurchasePriceSchedules
func (r ApiInAppPurchasePriceSchedulesGetInstanceRequest) FieldsInAppPurchasePriceSchedules(fieldsInAppPurchasePriceSchedules []string) ApiInAppPurchasePriceSchedulesGetInstanceRequest {
	r.fieldsInAppPurchasePriceSchedules = &fieldsInAppPurchasePriceSchedules
	return r
}

// comma-separated list of relationships to include
func (r ApiInAppPurchasePriceSchedulesGetInstanceRequest) Include(include []string) ApiInAppPurchasePriceSchedulesGetInstanceRequest {
	r.include = &include
	return r
}

// the fields to include for returned resources of type inAppPurchasePrices
func (r ApiInAppPurchasePriceSchedulesGetInstanceRequest) FieldsInAppPurchasePrices(fieldsInAppPurchasePrices []string) ApiInAppPurchasePriceSchedulesGetInstanceRequest {
	r.fieldsInAppPurchasePrices = &fieldsInAppPurchasePrices
	return r
}

// the fields to include for returned resources of type territories
func (r ApiInAppPurchasePriceSchedulesGetInstanceRequest) FieldsTerritories(fieldsTerritories []string) ApiInAppPurchasePriceSchedulesGetInstanceRequest {
	r.fieldsTerritories = &fieldsTerritories
	return r
}

// maximum number of related automaticPrices returned (when they are included)
func (r ApiInAppPurchasePriceSchedulesGetInstanceRequest) LimitAutomaticPrices(limitAutomaticPrices int32) ApiInAppPurchasePriceSchedulesGetInstanceRequest {
	r.limitAutomaticPrices = &limitAutomaticPrices
	return r
}

// maximum number of related manualPrices returned (when they are included)
func (r ApiInAppPurchasePriceSchedulesGetInstanceRequest) LimitManualPrices(limitManualPrices int32) ApiInAppPurchasePriceSchedulesGetInstanceRequest {
	r.limitManualPrices = &limitManualPrices
	return r
}

func (r ApiInAppPurchasePriceSchedulesGetInstanceRequest) Execute() (*InAppPurchasePriceScheduleResponse, *http.Response, error) {
	return r.ApiService.InAppPurchasePriceSchedulesGetInstanceExecute(r)
}

/*
InAppPurchasePriceSchedulesGetInstance Method for InAppPurchasePriceSchedulesGetInstance

	@param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
	@param id the id of the requested resource
	@return ApiInAppPurchasePriceSchedulesGetInstanceRequest
*/
func (a *InAppPurchasePriceSchedulesApiService) InAppPurchasePriceSchedulesGetInstance(ctx context.Context, id string) ApiInAppPurchasePriceSchedulesGetInstanceRequest {
	return ApiInAppPurchasePriceSchedulesGetInstanceRequest{
		ApiService: a,
		ctx:        ctx,
		id:         id,
	}
}

// Execute executes the request
//
//	@return InAppPurchasePriceScheduleResponse
func (a *InAppPurchasePriceSchedulesApiService) InAppPurchasePriceSchedulesGetInstanceExecute(r ApiInAppPurchasePriceSchedulesGetInstanceRequest) (*InAppPurchasePriceScheduleResponse, *http.Response, error) {
	var (
		localVarHTTPMethod  = http.MethodGet
		localVarPostBody    interface{}
		formFiles           []formFile
		localVarReturnValue *InAppPurchasePriceScheduleResponse
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "InAppPurchasePriceSchedulesApiService.InAppPurchasePriceSchedulesGetInstance")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/inAppPurchasePriceSchedules/{id}"
	localVarPath = strings.Replace(localVarPath, "{"+"id"+"}", url.PathEscape(parameterValueToString(r.id, "id")), -1)

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}

	if r.fieldsInAppPurchasePriceSchedules != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "fields[inAppPurchasePriceSchedules]", r.fieldsInAppPurchasePriceSchedules, "csv")
	}
	if r.include != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "include", r.include, "csv")
	}
	if r.fieldsInAppPurchasePrices != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "fields[inAppPurchasePrices]", r.fieldsInAppPurchasePrices, "csv")
	}
	if r.fieldsTerritories != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "fields[territories]", r.fieldsTerritories, "csv")
	}
	if r.limitAutomaticPrices != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "limit[automaticPrices]", r.limitAutomaticPrices, "")
	}
	if r.limitManualPrices != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "limit[manualPrices]", r.limitManualPrices, "")
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

type ApiInAppPurchasePriceSchedulesManualPricesGetToManyRelatedRequest struct {
	ctx                            context.Context
	ApiService                     *InAppPurchasePriceSchedulesApiService
	id                             string
	filterTerritory                *[]string
	fieldsInAppPurchasePricePoints *[]string
	fieldsInAppPurchasePrices      *[]string
	fieldsTerritories              *[]string
	limit                          *int32
	include                        *[]string
}

// filter by id(s) of related &#39;territory&#39;
func (r ApiInAppPurchasePriceSchedulesManualPricesGetToManyRelatedRequest) FilterTerritory(filterTerritory []string) ApiInAppPurchasePriceSchedulesManualPricesGetToManyRelatedRequest {
	r.filterTerritory = &filterTerritory
	return r
}

// the fields to include for returned resources of type inAppPurchasePricePoints
func (r ApiInAppPurchasePriceSchedulesManualPricesGetToManyRelatedRequest) FieldsInAppPurchasePricePoints(fieldsInAppPurchasePricePoints []string) ApiInAppPurchasePriceSchedulesManualPricesGetToManyRelatedRequest {
	r.fieldsInAppPurchasePricePoints = &fieldsInAppPurchasePricePoints
	return r
}

// the fields to include for returned resources of type inAppPurchasePrices
func (r ApiInAppPurchasePriceSchedulesManualPricesGetToManyRelatedRequest) FieldsInAppPurchasePrices(fieldsInAppPurchasePrices []string) ApiInAppPurchasePriceSchedulesManualPricesGetToManyRelatedRequest {
	r.fieldsInAppPurchasePrices = &fieldsInAppPurchasePrices
	return r
}

// the fields to include for returned resources of type territories
func (r ApiInAppPurchasePriceSchedulesManualPricesGetToManyRelatedRequest) FieldsTerritories(fieldsTerritories []string) ApiInAppPurchasePriceSchedulesManualPricesGetToManyRelatedRequest {
	r.fieldsTerritories = &fieldsTerritories
	return r
}

// maximum resources per page
func (r ApiInAppPurchasePriceSchedulesManualPricesGetToManyRelatedRequest) Limit(limit int32) ApiInAppPurchasePriceSchedulesManualPricesGetToManyRelatedRequest {
	r.limit = &limit
	return r
}

// comma-separated list of relationships to include
func (r ApiInAppPurchasePriceSchedulesManualPricesGetToManyRelatedRequest) Include(include []string) ApiInAppPurchasePriceSchedulesManualPricesGetToManyRelatedRequest {
	r.include = &include
	return r
}

func (r ApiInAppPurchasePriceSchedulesManualPricesGetToManyRelatedRequest) Execute() (*InAppPurchasePricesResponse, *http.Response, error) {
	return r.ApiService.InAppPurchasePriceSchedulesManualPricesGetToManyRelatedExecute(r)
}

/*
InAppPurchasePriceSchedulesManualPricesGetToManyRelated Method for InAppPurchasePriceSchedulesManualPricesGetToManyRelated

	@param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
	@param id the id of the requested resource
	@return ApiInAppPurchasePriceSchedulesManualPricesGetToManyRelatedRequest
*/
func (a *InAppPurchasePriceSchedulesApiService) InAppPurchasePriceSchedulesManualPricesGetToManyRelated(ctx context.Context, id string) ApiInAppPurchasePriceSchedulesManualPricesGetToManyRelatedRequest {
	return ApiInAppPurchasePriceSchedulesManualPricesGetToManyRelatedRequest{
		ApiService: a,
		ctx:        ctx,
		id:         id,
	}
}

// Execute executes the request
//
//	@return InAppPurchasePricesResponse
func (a *InAppPurchasePriceSchedulesApiService) InAppPurchasePriceSchedulesManualPricesGetToManyRelatedExecute(r ApiInAppPurchasePriceSchedulesManualPricesGetToManyRelatedRequest) (*InAppPurchasePricesResponse, *http.Response, error) {
	var (
		localVarHTTPMethod  = http.MethodGet
		localVarPostBody    interface{}
		formFiles           []formFile
		localVarReturnValue *InAppPurchasePricesResponse
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "InAppPurchasePriceSchedulesApiService.InAppPurchasePriceSchedulesManualPricesGetToManyRelated")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/inAppPurchasePriceSchedules/{id}/manualPrices"
	localVarPath = strings.Replace(localVarPath, "{"+"id"+"}", url.PathEscape(parameterValueToString(r.id, "id")), -1)

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}

	if r.filterTerritory != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "filter[territory]", r.filterTerritory, "csv")
	}
	if r.fieldsInAppPurchasePricePoints != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "fields[inAppPurchasePricePoints]", r.fieldsInAppPurchasePricePoints, "csv")
	}
	if r.fieldsInAppPurchasePrices != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "fields[inAppPurchasePrices]", r.fieldsInAppPurchasePrices, "csv")
	}
	if r.fieldsTerritories != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "fields[territories]", r.fieldsTerritories, "csv")
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
