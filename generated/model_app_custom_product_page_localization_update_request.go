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

// checks if the AppCustomProductPageLocalizationUpdateRequest type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &AppCustomProductPageLocalizationUpdateRequest{}

// AppCustomProductPageLocalizationUpdateRequest struct for AppCustomProductPageLocalizationUpdateRequest
type AppCustomProductPageLocalizationUpdateRequest struct {
	Data AppCustomProductPageLocalizationUpdateRequestData `json:"data"`
}

// NewAppCustomProductPageLocalizationUpdateRequest instantiates a new AppCustomProductPageLocalizationUpdateRequest object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewAppCustomProductPageLocalizationUpdateRequest(data AppCustomProductPageLocalizationUpdateRequestData) *AppCustomProductPageLocalizationUpdateRequest {
	this := AppCustomProductPageLocalizationUpdateRequest{}
	this.Data = data
	return &this
}

// NewAppCustomProductPageLocalizationUpdateRequestWithDefaults instantiates a new AppCustomProductPageLocalizationUpdateRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAppCustomProductPageLocalizationUpdateRequestWithDefaults() *AppCustomProductPageLocalizationUpdateRequest {
	this := AppCustomProductPageLocalizationUpdateRequest{}
	return &this
}

// GetData returns the Data field value
func (o *AppCustomProductPageLocalizationUpdateRequest) GetData() AppCustomProductPageLocalizationUpdateRequestData {
	if o == nil {
		var ret AppCustomProductPageLocalizationUpdateRequestData
		return ret
	}

	return o.Data
}

// GetDataOk returns a tuple with the Data field value
// and a boolean to check if the value has been set.
func (o *AppCustomProductPageLocalizationUpdateRequest) GetDataOk() (*AppCustomProductPageLocalizationUpdateRequestData, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Data, true
}

// SetData sets field value
func (o *AppCustomProductPageLocalizationUpdateRequest) SetData(v AppCustomProductPageLocalizationUpdateRequestData) {
	o.Data = v
}

func (o AppCustomProductPageLocalizationUpdateRequest) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o AppCustomProductPageLocalizationUpdateRequest) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["data"] = o.Data
	return toSerialize, nil
}

type NullableAppCustomProductPageLocalizationUpdateRequest struct {
	value *AppCustomProductPageLocalizationUpdateRequest
	isSet bool
}

func (v NullableAppCustomProductPageLocalizationUpdateRequest) Get() *AppCustomProductPageLocalizationUpdateRequest {
	return v.value
}

func (v *NullableAppCustomProductPageLocalizationUpdateRequest) Set(val *AppCustomProductPageLocalizationUpdateRequest) {
	v.value = val
	v.isSet = true
}

func (v NullableAppCustomProductPageLocalizationUpdateRequest) IsSet() bool {
	return v.isSet
}

func (v *NullableAppCustomProductPageLocalizationUpdateRequest) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableAppCustomProductPageLocalizationUpdateRequest(val *AppCustomProductPageLocalizationUpdateRequest) *NullableAppCustomProductPageLocalizationUpdateRequest {
	return &NullableAppCustomProductPageLocalizationUpdateRequest{value: val, isSet: true}
}

func (v NullableAppCustomProductPageLocalizationUpdateRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableAppCustomProductPageLocalizationUpdateRequest) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
