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

// checks if the AppCategoryAttributes type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &AppCategoryAttributes{}

// AppCategoryAttributes struct for AppCategoryAttributes
type AppCategoryAttributes struct {
	Platforms []Platform `json:"platforms,omitempty"`
}

// NewAppCategoryAttributes instantiates a new AppCategoryAttributes object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewAppCategoryAttributes() *AppCategoryAttributes {
	this := AppCategoryAttributes{}
	return &this
}

// NewAppCategoryAttributesWithDefaults instantiates a new AppCategoryAttributes object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAppCategoryAttributesWithDefaults() *AppCategoryAttributes {
	this := AppCategoryAttributes{}
	return &this
}

// GetPlatforms returns the Platforms field value if set, zero value otherwise.
func (o *AppCategoryAttributes) GetPlatforms() []Platform {
	if o == nil || IsNil(o.Platforms) {
		var ret []Platform
		return ret
	}
	return o.Platforms
}

// GetPlatformsOk returns a tuple with the Platforms field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AppCategoryAttributes) GetPlatformsOk() ([]Platform, bool) {
	if o == nil || IsNil(o.Platforms) {
		return nil, false
	}
	return o.Platforms, true
}

// HasPlatforms returns a boolean if a field has been set.
func (o *AppCategoryAttributes) HasPlatforms() bool {
	if o != nil && !IsNil(o.Platforms) {
		return true
	}

	return false
}

// SetPlatforms gets a reference to the given []Platform and assigns it to the Platforms field.
func (o *AppCategoryAttributes) SetPlatforms(v []Platform) {
	o.Platforms = v
}

func (o AppCategoryAttributes) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o AppCategoryAttributes) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.Platforms) {
		toSerialize["platforms"] = o.Platforms
	}
	return toSerialize, nil
}

type NullableAppCategoryAttributes struct {
	value *AppCategoryAttributes
	isSet bool
}

func (v NullableAppCategoryAttributes) Get() *AppCategoryAttributes {
	return v.value
}

func (v *NullableAppCategoryAttributes) Set(val *AppCategoryAttributes) {
	v.value = val
	v.isSet = true
}

func (v NullableAppCategoryAttributes) IsSet() bool {
	return v.isSet
}

func (v *NullableAppCategoryAttributes) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableAppCategoryAttributes(val *AppCategoryAttributes) *NullableAppCategoryAttributes {
	return &NullableAppCategoryAttributes{value: val, isSet: true}
}

func (v NullableAppCategoryAttributes) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableAppCategoryAttributes) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
