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

// checks if the AppClipAdvancedExperienceImageUpdateRequestDataAttributes type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &AppClipAdvancedExperienceImageUpdateRequestDataAttributes{}

// AppClipAdvancedExperienceImageUpdateRequestDataAttributes struct for AppClipAdvancedExperienceImageUpdateRequestDataAttributes
type AppClipAdvancedExperienceImageUpdateRequestDataAttributes struct {
	SourceFileChecksum *string `json:"sourceFileChecksum,omitempty"`
	Uploaded           *bool   `json:"uploaded,omitempty"`
}

// NewAppClipAdvancedExperienceImageUpdateRequestDataAttributes instantiates a new AppClipAdvancedExperienceImageUpdateRequestDataAttributes object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewAppClipAdvancedExperienceImageUpdateRequestDataAttributes() *AppClipAdvancedExperienceImageUpdateRequestDataAttributes {
	this := AppClipAdvancedExperienceImageUpdateRequestDataAttributes{}
	return &this
}

// NewAppClipAdvancedExperienceImageUpdateRequestDataAttributesWithDefaults instantiates a new AppClipAdvancedExperienceImageUpdateRequestDataAttributes object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAppClipAdvancedExperienceImageUpdateRequestDataAttributesWithDefaults() *AppClipAdvancedExperienceImageUpdateRequestDataAttributes {
	this := AppClipAdvancedExperienceImageUpdateRequestDataAttributes{}
	return &this
}

// GetSourceFileChecksum returns the SourceFileChecksum field value if set, zero value otherwise.
func (o *AppClipAdvancedExperienceImageUpdateRequestDataAttributes) GetSourceFileChecksum() string {
	if o == nil || IsNil(o.SourceFileChecksum) {
		var ret string
		return ret
	}
	return *o.SourceFileChecksum
}

// GetSourceFileChecksumOk returns a tuple with the SourceFileChecksum field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AppClipAdvancedExperienceImageUpdateRequestDataAttributes) GetSourceFileChecksumOk() (*string, bool) {
	if o == nil || IsNil(o.SourceFileChecksum) {
		return nil, false
	}
	return o.SourceFileChecksum, true
}

// HasSourceFileChecksum returns a boolean if a field has been set.
func (o *AppClipAdvancedExperienceImageUpdateRequestDataAttributes) HasSourceFileChecksum() bool {
	if o != nil && !IsNil(o.SourceFileChecksum) {
		return true
	}

	return false
}

// SetSourceFileChecksum gets a reference to the given string and assigns it to the SourceFileChecksum field.
func (o *AppClipAdvancedExperienceImageUpdateRequestDataAttributes) SetSourceFileChecksum(v string) {
	o.SourceFileChecksum = &v
}

// GetUploaded returns the Uploaded field value if set, zero value otherwise.
func (o *AppClipAdvancedExperienceImageUpdateRequestDataAttributes) GetUploaded() bool {
	if o == nil || IsNil(o.Uploaded) {
		var ret bool
		return ret
	}
	return *o.Uploaded
}

// GetUploadedOk returns a tuple with the Uploaded field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AppClipAdvancedExperienceImageUpdateRequestDataAttributes) GetUploadedOk() (*bool, bool) {
	if o == nil || IsNil(o.Uploaded) {
		return nil, false
	}
	return o.Uploaded, true
}

// HasUploaded returns a boolean if a field has been set.
func (o *AppClipAdvancedExperienceImageUpdateRequestDataAttributes) HasUploaded() bool {
	if o != nil && !IsNil(o.Uploaded) {
		return true
	}

	return false
}

// SetUploaded gets a reference to the given bool and assigns it to the Uploaded field.
func (o *AppClipAdvancedExperienceImageUpdateRequestDataAttributes) SetUploaded(v bool) {
	o.Uploaded = &v
}

func (o AppClipAdvancedExperienceImageUpdateRequestDataAttributes) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o AppClipAdvancedExperienceImageUpdateRequestDataAttributes) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.SourceFileChecksum) {
		toSerialize["sourceFileChecksum"] = o.SourceFileChecksum
	}
	if !IsNil(o.Uploaded) {
		toSerialize["uploaded"] = o.Uploaded
	}
	return toSerialize, nil
}

type NullableAppClipAdvancedExperienceImageUpdateRequestDataAttributes struct {
	value *AppClipAdvancedExperienceImageUpdateRequestDataAttributes
	isSet bool
}

func (v NullableAppClipAdvancedExperienceImageUpdateRequestDataAttributes) Get() *AppClipAdvancedExperienceImageUpdateRequestDataAttributes {
	return v.value
}

func (v *NullableAppClipAdvancedExperienceImageUpdateRequestDataAttributes) Set(val *AppClipAdvancedExperienceImageUpdateRequestDataAttributes) {
	v.value = val
	v.isSet = true
}

func (v NullableAppClipAdvancedExperienceImageUpdateRequestDataAttributes) IsSet() bool {
	return v.isSet
}

func (v *NullableAppClipAdvancedExperienceImageUpdateRequestDataAttributes) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableAppClipAdvancedExperienceImageUpdateRequestDataAttributes(val *AppClipAdvancedExperienceImageUpdateRequestDataAttributes) *NullableAppClipAdvancedExperienceImageUpdateRequestDataAttributes {
	return &NullableAppClipAdvancedExperienceImageUpdateRequestDataAttributes{value: val, isSet: true}
}

func (v NullableAppClipAdvancedExperienceImageUpdateRequestDataAttributes) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableAppClipAdvancedExperienceImageUpdateRequestDataAttributes) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
