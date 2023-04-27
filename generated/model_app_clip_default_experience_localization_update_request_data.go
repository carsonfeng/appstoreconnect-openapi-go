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

// checks if the AppClipDefaultExperienceLocalizationUpdateRequestData type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &AppClipDefaultExperienceLocalizationUpdateRequestData{}

// AppClipDefaultExperienceLocalizationUpdateRequestData struct for AppClipDefaultExperienceLocalizationUpdateRequestData
type AppClipDefaultExperienceLocalizationUpdateRequestData struct {
	Type       string                                                           `json:"type"`
	Id         string                                                           `json:"id"`
	Attributes *AppClipDefaultExperienceLocalizationUpdateRequestDataAttributes `json:"attributes,omitempty"`
}

// NewAppClipDefaultExperienceLocalizationUpdateRequestData instantiates a new AppClipDefaultExperienceLocalizationUpdateRequestData object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewAppClipDefaultExperienceLocalizationUpdateRequestData(type_ string, id string) *AppClipDefaultExperienceLocalizationUpdateRequestData {
	this := AppClipDefaultExperienceLocalizationUpdateRequestData{}
	this.Type = type_
	this.Id = id
	return &this
}

// NewAppClipDefaultExperienceLocalizationUpdateRequestDataWithDefaults instantiates a new AppClipDefaultExperienceLocalizationUpdateRequestData object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAppClipDefaultExperienceLocalizationUpdateRequestDataWithDefaults() *AppClipDefaultExperienceLocalizationUpdateRequestData {
	this := AppClipDefaultExperienceLocalizationUpdateRequestData{}
	return &this
}

// GetType returns the Type field value
func (o *AppClipDefaultExperienceLocalizationUpdateRequestData) GetType() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Type
}

// GetTypeOk returns a tuple with the Type field value
// and a boolean to check if the value has been set.
func (o *AppClipDefaultExperienceLocalizationUpdateRequestData) GetTypeOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Type, true
}

// SetType sets field value
func (o *AppClipDefaultExperienceLocalizationUpdateRequestData) SetType(v string) {
	o.Type = v
}

// GetId returns the Id field value
func (o *AppClipDefaultExperienceLocalizationUpdateRequestData) GetId() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Id
}

// GetIdOk returns a tuple with the Id field value
// and a boolean to check if the value has been set.
func (o *AppClipDefaultExperienceLocalizationUpdateRequestData) GetIdOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Id, true
}

// SetId sets field value
func (o *AppClipDefaultExperienceLocalizationUpdateRequestData) SetId(v string) {
	o.Id = v
}

// GetAttributes returns the Attributes field value if set, zero value otherwise.
func (o *AppClipDefaultExperienceLocalizationUpdateRequestData) GetAttributes() AppClipDefaultExperienceLocalizationUpdateRequestDataAttributes {
	if o == nil || IsNil(o.Attributes) {
		var ret AppClipDefaultExperienceLocalizationUpdateRequestDataAttributes
		return ret
	}
	return *o.Attributes
}

// GetAttributesOk returns a tuple with the Attributes field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AppClipDefaultExperienceLocalizationUpdateRequestData) GetAttributesOk() (*AppClipDefaultExperienceLocalizationUpdateRequestDataAttributes, bool) {
	if o == nil || IsNil(o.Attributes) {
		return nil, false
	}
	return o.Attributes, true
}

// HasAttributes returns a boolean if a field has been set.
func (o *AppClipDefaultExperienceLocalizationUpdateRequestData) HasAttributes() bool {
	if o != nil && !IsNil(o.Attributes) {
		return true
	}

	return false
}

// SetAttributes gets a reference to the given AppClipDefaultExperienceLocalizationUpdateRequestDataAttributes and assigns it to the Attributes field.
func (o *AppClipDefaultExperienceLocalizationUpdateRequestData) SetAttributes(v AppClipDefaultExperienceLocalizationUpdateRequestDataAttributes) {
	o.Attributes = &v
}

func (o AppClipDefaultExperienceLocalizationUpdateRequestData) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o AppClipDefaultExperienceLocalizationUpdateRequestData) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["type"] = o.Type
	toSerialize["id"] = o.Id
	if !IsNil(o.Attributes) {
		toSerialize["attributes"] = o.Attributes
	}
	return toSerialize, nil
}

type NullableAppClipDefaultExperienceLocalizationUpdateRequestData struct {
	value *AppClipDefaultExperienceLocalizationUpdateRequestData
	isSet bool
}

func (v NullableAppClipDefaultExperienceLocalizationUpdateRequestData) Get() *AppClipDefaultExperienceLocalizationUpdateRequestData {
	return v.value
}

func (v *NullableAppClipDefaultExperienceLocalizationUpdateRequestData) Set(val *AppClipDefaultExperienceLocalizationUpdateRequestData) {
	v.value = val
	v.isSet = true
}

func (v NullableAppClipDefaultExperienceLocalizationUpdateRequestData) IsSet() bool {
	return v.isSet
}

func (v *NullableAppClipDefaultExperienceLocalizationUpdateRequestData) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableAppClipDefaultExperienceLocalizationUpdateRequestData(val *AppClipDefaultExperienceLocalizationUpdateRequestData) *NullableAppClipDefaultExperienceLocalizationUpdateRequestData {
	return &NullableAppClipDefaultExperienceLocalizationUpdateRequestData{value: val, isSet: true}
}

func (v NullableAppClipDefaultExperienceLocalizationUpdateRequestData) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableAppClipDefaultExperienceLocalizationUpdateRequestData) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
