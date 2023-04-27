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

// checks if the AppEventScreenshotCreateRequestDataRelationshipsAppEventLocalization type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &AppEventScreenshotCreateRequestDataRelationshipsAppEventLocalization{}

// AppEventScreenshotCreateRequestDataRelationshipsAppEventLocalization struct for AppEventScreenshotCreateRequestDataRelationshipsAppEventLocalization
type AppEventScreenshotCreateRequestDataRelationshipsAppEventLocalization struct {
	Data AppEventScreenshotRelationshipsAppEventLocalizationData `json:"data"`
}

// NewAppEventScreenshotCreateRequestDataRelationshipsAppEventLocalization instantiates a new AppEventScreenshotCreateRequestDataRelationshipsAppEventLocalization object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewAppEventScreenshotCreateRequestDataRelationshipsAppEventLocalization(data AppEventScreenshotRelationshipsAppEventLocalizationData) *AppEventScreenshotCreateRequestDataRelationshipsAppEventLocalization {
	this := AppEventScreenshotCreateRequestDataRelationshipsAppEventLocalization{}
	this.Data = data
	return &this
}

// NewAppEventScreenshotCreateRequestDataRelationshipsAppEventLocalizationWithDefaults instantiates a new AppEventScreenshotCreateRequestDataRelationshipsAppEventLocalization object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAppEventScreenshotCreateRequestDataRelationshipsAppEventLocalizationWithDefaults() *AppEventScreenshotCreateRequestDataRelationshipsAppEventLocalization {
	this := AppEventScreenshotCreateRequestDataRelationshipsAppEventLocalization{}
	return &this
}

// GetData returns the Data field value
func (o *AppEventScreenshotCreateRequestDataRelationshipsAppEventLocalization) GetData() AppEventScreenshotRelationshipsAppEventLocalizationData {
	if o == nil {
		var ret AppEventScreenshotRelationshipsAppEventLocalizationData
		return ret
	}

	return o.Data
}

// GetDataOk returns a tuple with the Data field value
// and a boolean to check if the value has been set.
func (o *AppEventScreenshotCreateRequestDataRelationshipsAppEventLocalization) GetDataOk() (*AppEventScreenshotRelationshipsAppEventLocalizationData, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Data, true
}

// SetData sets field value
func (o *AppEventScreenshotCreateRequestDataRelationshipsAppEventLocalization) SetData(v AppEventScreenshotRelationshipsAppEventLocalizationData) {
	o.Data = v
}

func (o AppEventScreenshotCreateRequestDataRelationshipsAppEventLocalization) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o AppEventScreenshotCreateRequestDataRelationshipsAppEventLocalization) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["data"] = o.Data
	return toSerialize, nil
}

type NullableAppEventScreenshotCreateRequestDataRelationshipsAppEventLocalization struct {
	value *AppEventScreenshotCreateRequestDataRelationshipsAppEventLocalization
	isSet bool
}

func (v NullableAppEventScreenshotCreateRequestDataRelationshipsAppEventLocalization) Get() *AppEventScreenshotCreateRequestDataRelationshipsAppEventLocalization {
	return v.value
}

func (v *NullableAppEventScreenshotCreateRequestDataRelationshipsAppEventLocalization) Set(val *AppEventScreenshotCreateRequestDataRelationshipsAppEventLocalization) {
	v.value = val
	v.isSet = true
}

func (v NullableAppEventScreenshotCreateRequestDataRelationshipsAppEventLocalization) IsSet() bool {
	return v.isSet
}

func (v *NullableAppEventScreenshotCreateRequestDataRelationshipsAppEventLocalization) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableAppEventScreenshotCreateRequestDataRelationshipsAppEventLocalization(val *AppEventScreenshotCreateRequestDataRelationshipsAppEventLocalization) *NullableAppEventScreenshotCreateRequestDataRelationshipsAppEventLocalization {
	return &NullableAppEventScreenshotCreateRequestDataRelationshipsAppEventLocalization{value: val, isSet: true}
}

func (v NullableAppEventScreenshotCreateRequestDataRelationshipsAppEventLocalization) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableAppEventScreenshotCreateRequestDataRelationshipsAppEventLocalization) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
