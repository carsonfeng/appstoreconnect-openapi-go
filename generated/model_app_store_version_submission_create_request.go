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

// checks if the AppStoreVersionSubmissionCreateRequest type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &AppStoreVersionSubmissionCreateRequest{}

// AppStoreVersionSubmissionCreateRequest struct for AppStoreVersionSubmissionCreateRequest
type AppStoreVersionSubmissionCreateRequest struct {
	Data AppStoreVersionSubmissionCreateRequestData `json:"data"`
}

// NewAppStoreVersionSubmissionCreateRequest instantiates a new AppStoreVersionSubmissionCreateRequest object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewAppStoreVersionSubmissionCreateRequest(data AppStoreVersionSubmissionCreateRequestData) *AppStoreVersionSubmissionCreateRequest {
	this := AppStoreVersionSubmissionCreateRequest{}
	this.Data = data
	return &this
}

// NewAppStoreVersionSubmissionCreateRequestWithDefaults instantiates a new AppStoreVersionSubmissionCreateRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAppStoreVersionSubmissionCreateRequestWithDefaults() *AppStoreVersionSubmissionCreateRequest {
	this := AppStoreVersionSubmissionCreateRequest{}
	return &this
}

// GetData returns the Data field value
func (o *AppStoreVersionSubmissionCreateRequest) GetData() AppStoreVersionSubmissionCreateRequestData {
	if o == nil {
		var ret AppStoreVersionSubmissionCreateRequestData
		return ret
	}

	return o.Data
}

// GetDataOk returns a tuple with the Data field value
// and a boolean to check if the value has been set.
func (o *AppStoreVersionSubmissionCreateRequest) GetDataOk() (*AppStoreVersionSubmissionCreateRequestData, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Data, true
}

// SetData sets field value
func (o *AppStoreVersionSubmissionCreateRequest) SetData(v AppStoreVersionSubmissionCreateRequestData) {
	o.Data = v
}

func (o AppStoreVersionSubmissionCreateRequest) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o AppStoreVersionSubmissionCreateRequest) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["data"] = o.Data
	return toSerialize, nil
}

type NullableAppStoreVersionSubmissionCreateRequest struct {
	value *AppStoreVersionSubmissionCreateRequest
	isSet bool
}

func (v NullableAppStoreVersionSubmissionCreateRequest) Get() *AppStoreVersionSubmissionCreateRequest {
	return v.value
}

func (v *NullableAppStoreVersionSubmissionCreateRequest) Set(val *AppStoreVersionSubmissionCreateRequest) {
	v.value = val
	v.isSet = true
}

func (v NullableAppStoreVersionSubmissionCreateRequest) IsSet() bool {
	return v.isSet
}

func (v *NullableAppStoreVersionSubmissionCreateRequest) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableAppStoreVersionSubmissionCreateRequest(val *AppStoreVersionSubmissionCreateRequest) *NullableAppStoreVersionSubmissionCreateRequest {
	return &NullableAppStoreVersionSubmissionCreateRequest{value: val, isSet: true}
}

func (v NullableAppStoreVersionSubmissionCreateRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableAppStoreVersionSubmissionCreateRequest) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}