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

// checks if the AppStoreVersionExperimentUpdateRequestData type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &AppStoreVersionExperimentUpdateRequestData{}

// AppStoreVersionExperimentUpdateRequestData struct for AppStoreVersionExperimentUpdateRequestData
type AppStoreVersionExperimentUpdateRequestData struct {
	Type       string                                                `json:"type"`
	Id         string                                                `json:"id"`
	Attributes *AppStoreVersionExperimentUpdateRequestDataAttributes `json:"attributes,omitempty"`
}

// NewAppStoreVersionExperimentUpdateRequestData instantiates a new AppStoreVersionExperimentUpdateRequestData object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewAppStoreVersionExperimentUpdateRequestData(type_ string, id string) *AppStoreVersionExperimentUpdateRequestData {
	this := AppStoreVersionExperimentUpdateRequestData{}
	this.Type = type_
	this.Id = id
	return &this
}

// NewAppStoreVersionExperimentUpdateRequestDataWithDefaults instantiates a new AppStoreVersionExperimentUpdateRequestData object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAppStoreVersionExperimentUpdateRequestDataWithDefaults() *AppStoreVersionExperimentUpdateRequestData {
	this := AppStoreVersionExperimentUpdateRequestData{}
	return &this
}

// GetType returns the Type field value
func (o *AppStoreVersionExperimentUpdateRequestData) GetType() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Type
}

// GetTypeOk returns a tuple with the Type field value
// and a boolean to check if the value has been set.
func (o *AppStoreVersionExperimentUpdateRequestData) GetTypeOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Type, true
}

// SetType sets field value
func (o *AppStoreVersionExperimentUpdateRequestData) SetType(v string) {
	o.Type = v
}

// GetId returns the Id field value
func (o *AppStoreVersionExperimentUpdateRequestData) GetId() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Id
}

// GetIdOk returns a tuple with the Id field value
// and a boolean to check if the value has been set.
func (o *AppStoreVersionExperimentUpdateRequestData) GetIdOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Id, true
}

// SetId sets field value
func (o *AppStoreVersionExperimentUpdateRequestData) SetId(v string) {
	o.Id = v
}

// GetAttributes returns the Attributes field value if set, zero value otherwise.
func (o *AppStoreVersionExperimentUpdateRequestData) GetAttributes() AppStoreVersionExperimentUpdateRequestDataAttributes {
	if o == nil || IsNil(o.Attributes) {
		var ret AppStoreVersionExperimentUpdateRequestDataAttributes
		return ret
	}
	return *o.Attributes
}

// GetAttributesOk returns a tuple with the Attributes field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AppStoreVersionExperimentUpdateRequestData) GetAttributesOk() (*AppStoreVersionExperimentUpdateRequestDataAttributes, bool) {
	if o == nil || IsNil(o.Attributes) {
		return nil, false
	}
	return o.Attributes, true
}

// HasAttributes returns a boolean if a field has been set.
func (o *AppStoreVersionExperimentUpdateRequestData) HasAttributes() bool {
	if o != nil && !IsNil(o.Attributes) {
		return true
	}

	return false
}

// SetAttributes gets a reference to the given AppStoreVersionExperimentUpdateRequestDataAttributes and assigns it to the Attributes field.
func (o *AppStoreVersionExperimentUpdateRequestData) SetAttributes(v AppStoreVersionExperimentUpdateRequestDataAttributes) {
	o.Attributes = &v
}

func (o AppStoreVersionExperimentUpdateRequestData) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o AppStoreVersionExperimentUpdateRequestData) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["type"] = o.Type
	toSerialize["id"] = o.Id
	if !IsNil(o.Attributes) {
		toSerialize["attributes"] = o.Attributes
	}
	return toSerialize, nil
}

type NullableAppStoreVersionExperimentUpdateRequestData struct {
	value *AppStoreVersionExperimentUpdateRequestData
	isSet bool
}

func (v NullableAppStoreVersionExperimentUpdateRequestData) Get() *AppStoreVersionExperimentUpdateRequestData {
	return v.value
}

func (v *NullableAppStoreVersionExperimentUpdateRequestData) Set(val *AppStoreVersionExperimentUpdateRequestData) {
	v.value = val
	v.isSet = true
}

func (v NullableAppStoreVersionExperimentUpdateRequestData) IsSet() bool {
	return v.isSet
}

func (v *NullableAppStoreVersionExperimentUpdateRequestData) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableAppStoreVersionExperimentUpdateRequestData(val *AppStoreVersionExperimentUpdateRequestData) *NullableAppStoreVersionExperimentUpdateRequestData {
	return &NullableAppStoreVersionExperimentUpdateRequestData{value: val, isSet: true}
}

func (v NullableAppStoreVersionExperimentUpdateRequestData) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableAppStoreVersionExperimentUpdateRequestData) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
