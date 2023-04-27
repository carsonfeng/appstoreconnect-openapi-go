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

// checks if the BetaAppLocalizationUpdateRequest type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &BetaAppLocalizationUpdateRequest{}

// BetaAppLocalizationUpdateRequest struct for BetaAppLocalizationUpdateRequest
type BetaAppLocalizationUpdateRequest struct {
	Data BetaAppLocalizationUpdateRequestData `json:"data"`
}

// NewBetaAppLocalizationUpdateRequest instantiates a new BetaAppLocalizationUpdateRequest object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewBetaAppLocalizationUpdateRequest(data BetaAppLocalizationUpdateRequestData) *BetaAppLocalizationUpdateRequest {
	this := BetaAppLocalizationUpdateRequest{}
	this.Data = data
	return &this
}

// NewBetaAppLocalizationUpdateRequestWithDefaults instantiates a new BetaAppLocalizationUpdateRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewBetaAppLocalizationUpdateRequestWithDefaults() *BetaAppLocalizationUpdateRequest {
	this := BetaAppLocalizationUpdateRequest{}
	return &this
}

// GetData returns the Data field value
func (o *BetaAppLocalizationUpdateRequest) GetData() BetaAppLocalizationUpdateRequestData {
	if o == nil {
		var ret BetaAppLocalizationUpdateRequestData
		return ret
	}

	return o.Data
}

// GetDataOk returns a tuple with the Data field value
// and a boolean to check if the value has been set.
func (o *BetaAppLocalizationUpdateRequest) GetDataOk() (*BetaAppLocalizationUpdateRequestData, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Data, true
}

// SetData sets field value
func (o *BetaAppLocalizationUpdateRequest) SetData(v BetaAppLocalizationUpdateRequestData) {
	o.Data = v
}

func (o BetaAppLocalizationUpdateRequest) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o BetaAppLocalizationUpdateRequest) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["data"] = o.Data
	return toSerialize, nil
}

type NullableBetaAppLocalizationUpdateRequest struct {
	value *BetaAppLocalizationUpdateRequest
	isSet bool
}

func (v NullableBetaAppLocalizationUpdateRequest) Get() *BetaAppLocalizationUpdateRequest {
	return v.value
}

func (v *NullableBetaAppLocalizationUpdateRequest) Set(val *BetaAppLocalizationUpdateRequest) {
	v.value = val
	v.isSet = true
}

func (v NullableBetaAppLocalizationUpdateRequest) IsSet() bool {
	return v.isSet
}

func (v *NullableBetaAppLocalizationUpdateRequest) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableBetaAppLocalizationUpdateRequest(val *BetaAppLocalizationUpdateRequest) *NullableBetaAppLocalizationUpdateRequest {
	return &NullableBetaAppLocalizationUpdateRequest{value: val, isSet: true}
}

func (v NullableBetaAppLocalizationUpdateRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableBetaAppLocalizationUpdateRequest) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
