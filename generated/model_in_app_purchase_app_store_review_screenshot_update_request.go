/*
App Store Connect API

No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)

API version: 2.3
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package openapi

import (
	"encoding/json"
)

// checks if the InAppPurchaseAppStoreReviewScreenshotUpdateRequest type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &InAppPurchaseAppStoreReviewScreenshotUpdateRequest{}

// InAppPurchaseAppStoreReviewScreenshotUpdateRequest struct for InAppPurchaseAppStoreReviewScreenshotUpdateRequest
type InAppPurchaseAppStoreReviewScreenshotUpdateRequest struct {
	Data InAppPurchaseAppStoreReviewScreenshotUpdateRequestData `json:"data"`
}

// NewInAppPurchaseAppStoreReviewScreenshotUpdateRequest instantiates a new InAppPurchaseAppStoreReviewScreenshotUpdateRequest object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewInAppPurchaseAppStoreReviewScreenshotUpdateRequest(data InAppPurchaseAppStoreReviewScreenshotUpdateRequestData) *InAppPurchaseAppStoreReviewScreenshotUpdateRequest {
	this := InAppPurchaseAppStoreReviewScreenshotUpdateRequest{}
	this.Data = data
	return &this
}

// NewInAppPurchaseAppStoreReviewScreenshotUpdateRequestWithDefaults instantiates a new InAppPurchaseAppStoreReviewScreenshotUpdateRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewInAppPurchaseAppStoreReviewScreenshotUpdateRequestWithDefaults() *InAppPurchaseAppStoreReviewScreenshotUpdateRequest {
	this := InAppPurchaseAppStoreReviewScreenshotUpdateRequest{}
	return &this
}

// GetData returns the Data field value
func (o *InAppPurchaseAppStoreReviewScreenshotUpdateRequest) GetData() InAppPurchaseAppStoreReviewScreenshotUpdateRequestData {
	if o == nil {
		var ret InAppPurchaseAppStoreReviewScreenshotUpdateRequestData
		return ret
	}

	return o.Data
}

// GetDataOk returns a tuple with the Data field value
// and a boolean to check if the value has been set.
func (o *InAppPurchaseAppStoreReviewScreenshotUpdateRequest) GetDataOk() (*InAppPurchaseAppStoreReviewScreenshotUpdateRequestData, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Data, true
}

// SetData sets field value
func (o *InAppPurchaseAppStoreReviewScreenshotUpdateRequest) SetData(v InAppPurchaseAppStoreReviewScreenshotUpdateRequestData) {
	o.Data = v
}

func (o InAppPurchaseAppStoreReviewScreenshotUpdateRequest) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o InAppPurchaseAppStoreReviewScreenshotUpdateRequest) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["data"] = o.Data
	return toSerialize, nil
}

type NullableInAppPurchaseAppStoreReviewScreenshotUpdateRequest struct {
	value *InAppPurchaseAppStoreReviewScreenshotUpdateRequest
	isSet bool
}

func (v NullableInAppPurchaseAppStoreReviewScreenshotUpdateRequest) Get() *InAppPurchaseAppStoreReviewScreenshotUpdateRequest {
	return v.value
}

func (v *NullableInAppPurchaseAppStoreReviewScreenshotUpdateRequest) Set(val *InAppPurchaseAppStoreReviewScreenshotUpdateRequest) {
	v.value = val
	v.isSet = true
}

func (v NullableInAppPurchaseAppStoreReviewScreenshotUpdateRequest) IsSet() bool {
	return v.isSet
}

func (v *NullableInAppPurchaseAppStoreReviewScreenshotUpdateRequest) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableInAppPurchaseAppStoreReviewScreenshotUpdateRequest(val *InAppPurchaseAppStoreReviewScreenshotUpdateRequest) *NullableInAppPurchaseAppStoreReviewScreenshotUpdateRequest {
	return &NullableInAppPurchaseAppStoreReviewScreenshotUpdateRequest{value: val, isSet: true}
}

func (v NullableInAppPurchaseAppStoreReviewScreenshotUpdateRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableInAppPurchaseAppStoreReviewScreenshotUpdateRequest) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
