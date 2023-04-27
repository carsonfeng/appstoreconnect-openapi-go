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

// SubscriptionPricePointsApiService SubscriptionPricePointsApi service
type SubscriptionPricePointsApiService service

type ApiSubscriptionPricePointsEqualizationsGetToManyRelatedRequest struct {
	ctx                           context.Context
	ApiService                    *SubscriptionPricePointsApiService
	id                            string
	filterSubscription            *[]string
	filterTerritory               *[]string
	fieldsSubscriptionPricePoints *[]string
	fieldsTerritories             *[]string
	limit                         *int32
	include                       *[]string
}

// filter by id(s) of related &#39;subscription&#39;
func (r ApiSubscriptionPricePointsEqualizationsGetToManyRelatedRequest) FilterSubscription(filterSubscription []string) ApiSubscriptionPricePointsEqualizationsGetToManyRelatedRequest {
	r.filterSubscription = &filterSubscription
	return r
}

// filter by id(s) of related &#39;territory&#39;
func (r ApiSubscriptionPricePointsEqualizationsGetToManyRelatedRequest) FilterTerritory(filterTerritory []string) ApiSubscriptionPricePointsEqualizationsGetToManyRelatedRequest {
	r.filterTerritory = &filterTerritory
	return r
}

// the fields to include for returned resources of type subscriptionPricePoints
func (r ApiSubscriptionPricePointsEqualizationsGetToManyRelatedRequest) FieldsSubscriptionPricePoints(fieldsSubscriptionPricePoints []string) ApiSubscriptionPricePointsEqualizationsGetToManyRelatedRequest {
	r.fieldsSubscriptionPricePoints = &fieldsSubscriptionPricePoints
	return r
}

// the fields to include for returned resources of type territories
func (r ApiSubscriptionPricePointsEqualizationsGetToManyRelatedRequest) FieldsTerritories(fieldsTerritories []string) ApiSubscriptionPricePointsEqualizationsGetToManyRelatedRequest {
	r.fieldsTerritories = &fieldsTerritories
	return r
}

// maximum resources per page
func (r ApiSubscriptionPricePointsEqualizationsGetToManyRelatedRequest) Limit(limit int32) ApiSubscriptionPricePointsEqualizationsGetToManyRelatedRequest {
	r.limit = &limit
	return r
}

// comma-separated list of relationships to include
func (r ApiSubscriptionPricePointsEqualizationsGetToManyRelatedRequest) Include(include []string) ApiSubscriptionPricePointsEqualizationsGetToManyRelatedRequest {
	r.include = &include
	return r
}

func (r ApiSubscriptionPricePointsEqualizationsGetToManyRelatedRequest) Execute() (*SubscriptionPricePointsResponse, *http.Response, error) {
	return r.ApiService.SubscriptionPricePointsEqualizationsGetToManyRelatedExecute(r)
}

/*
SubscriptionPricePointsEqualizationsGetToManyRelated Method for SubscriptionPricePointsEqualizationsGetToManyRelated

	@param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
	@param id the id of the requested resource
	@return ApiSubscriptionPricePointsEqualizationsGetToManyRelatedRequest
*/
func (a *SubscriptionPricePointsApiService) SubscriptionPricePointsEqualizationsGetToManyRelated(ctx context.Context, id string) ApiSubscriptionPricePointsEqualizationsGetToManyRelatedRequest {
	return ApiSubscriptionPricePointsEqualizationsGetToManyRelatedRequest{
		ApiService: a,
		ctx:        ctx,
		id:         id,
	}
}

// Execute executes the request
//
//	@return SubscriptionPricePointsResponse
func (a *SubscriptionPricePointsApiService) SubscriptionPricePointsEqualizationsGetToManyRelatedExecute(r ApiSubscriptionPricePointsEqualizationsGetToManyRelatedRequest) (*SubscriptionPricePointsResponse, *http.Response, error) {
	var (
		localVarHTTPMethod  = http.MethodGet
		localVarPostBody    interface{}
		formFiles           []formFile
		localVarReturnValue *SubscriptionPricePointsResponse
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "SubscriptionPricePointsApiService.SubscriptionPricePointsEqualizationsGetToManyRelated")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/subscriptionPricePoints/{id}/equalizations"
	localVarPath = strings.Replace(localVarPath, "{"+"id"+"}", url.PathEscape(parameterValueToString(r.id, "id")), -1)

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}

	if r.filterSubscription != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "filter[subscription]", r.filterSubscription, "csv")
	}
	if r.filterTerritory != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "filter[territory]", r.filterTerritory, "csv")
	}
	if r.fieldsSubscriptionPricePoints != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "fields[subscriptionPricePoints]", r.fieldsSubscriptionPricePoints, "csv")
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
	localVarHTTPHeaderAccepts := []string{"application/json", "text/csv"}

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

type ApiSubscriptionPricePointsGetInstanceRequest struct {
	ctx                           context.Context
	ApiService                    *SubscriptionPricePointsApiService
	id                            string
	fieldsSubscriptionPricePoints *[]string
	include                       *[]string
}

// the fields to include for returned resources of type subscriptionPricePoints
func (r ApiSubscriptionPricePointsGetInstanceRequest) FieldsSubscriptionPricePoints(fieldsSubscriptionPricePoints []string) ApiSubscriptionPricePointsGetInstanceRequest {
	r.fieldsSubscriptionPricePoints = &fieldsSubscriptionPricePoints
	return r
}

// comma-separated list of relationships to include
func (r ApiSubscriptionPricePointsGetInstanceRequest) Include(include []string) ApiSubscriptionPricePointsGetInstanceRequest {
	r.include = &include
	return r
}

func (r ApiSubscriptionPricePointsGetInstanceRequest) Execute() (*SubscriptionPricePointResponse, *http.Response, error) {
	return r.ApiService.SubscriptionPricePointsGetInstanceExecute(r)
}

/*
SubscriptionPricePointsGetInstance Method for SubscriptionPricePointsGetInstance

	@param ctx context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
	@param id the id of the requested resource
	@return ApiSubscriptionPricePointsGetInstanceRequest
*/
func (a *SubscriptionPricePointsApiService) SubscriptionPricePointsGetInstance(ctx context.Context, id string) ApiSubscriptionPricePointsGetInstanceRequest {
	return ApiSubscriptionPricePointsGetInstanceRequest{
		ApiService: a,
		ctx:        ctx,
		id:         id,
	}
}

// Execute executes the request
//
//	@return SubscriptionPricePointResponse
func (a *SubscriptionPricePointsApiService) SubscriptionPricePointsGetInstanceExecute(r ApiSubscriptionPricePointsGetInstanceRequest) (*SubscriptionPricePointResponse, *http.Response, error) {
	var (
		localVarHTTPMethod  = http.MethodGet
		localVarPostBody    interface{}
		formFiles           []formFile
		localVarReturnValue *SubscriptionPricePointResponse
	)

	localBasePath, err := a.client.cfg.ServerURLWithContext(r.ctx, "SubscriptionPricePointsApiService.SubscriptionPricePointsGetInstance")
	if err != nil {
		return localVarReturnValue, nil, &GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/v1/subscriptionPricePoints/{id}"
	localVarPath = strings.Replace(localVarPath, "{"+"id"+"}", url.PathEscape(parameterValueToString(r.id, "id")), -1)

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := url.Values{}
	localVarFormParams := url.Values{}

	if r.fieldsSubscriptionPricePoints != nil {
		parameterAddToHeaderOrQuery(localVarQueryParams, "fields[subscriptionPricePoints]", r.fieldsSubscriptionPricePoints, "csv")
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
