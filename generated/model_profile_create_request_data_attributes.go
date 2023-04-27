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

// checks if the ProfileCreateRequestDataAttributes type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &ProfileCreateRequestDataAttributes{}

// ProfileCreateRequestDataAttributes struct for ProfileCreateRequestDataAttributes
type ProfileCreateRequestDataAttributes struct {
	Name        string `json:"name"`
	ProfileType string `json:"profileType"`
}

// NewProfileCreateRequestDataAttributes instantiates a new ProfileCreateRequestDataAttributes object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewProfileCreateRequestDataAttributes(name string, profileType string) *ProfileCreateRequestDataAttributes {
	this := ProfileCreateRequestDataAttributes{}
	this.Name = name
	this.ProfileType = profileType
	return &this
}

// NewProfileCreateRequestDataAttributesWithDefaults instantiates a new ProfileCreateRequestDataAttributes object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewProfileCreateRequestDataAttributesWithDefaults() *ProfileCreateRequestDataAttributes {
	this := ProfileCreateRequestDataAttributes{}
	return &this
}

// GetName returns the Name field value
func (o *ProfileCreateRequestDataAttributes) GetName() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Name
}

// GetNameOk returns a tuple with the Name field value
// and a boolean to check if the value has been set.
func (o *ProfileCreateRequestDataAttributes) GetNameOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Name, true
}

// SetName sets field value
func (o *ProfileCreateRequestDataAttributes) SetName(v string) {
	o.Name = v
}

// GetProfileType returns the ProfileType field value
func (o *ProfileCreateRequestDataAttributes) GetProfileType() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.ProfileType
}

// GetProfileTypeOk returns a tuple with the ProfileType field value
// and a boolean to check if the value has been set.
func (o *ProfileCreateRequestDataAttributes) GetProfileTypeOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.ProfileType, true
}

// SetProfileType sets field value
func (o *ProfileCreateRequestDataAttributes) SetProfileType(v string) {
	o.ProfileType = v
}

func (o ProfileCreateRequestDataAttributes) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o ProfileCreateRequestDataAttributes) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["name"] = o.Name
	toSerialize["profileType"] = o.ProfileType
	return toSerialize, nil
}

type NullableProfileCreateRequestDataAttributes struct {
	value *ProfileCreateRequestDataAttributes
	isSet bool
}

func (v NullableProfileCreateRequestDataAttributes) Get() *ProfileCreateRequestDataAttributes {
	return v.value
}

func (v *NullableProfileCreateRequestDataAttributes) Set(val *ProfileCreateRequestDataAttributes) {
	v.value = val
	v.isSet = true
}

func (v NullableProfileCreateRequestDataAttributes) IsSet() bool {
	return v.isSet
}

func (v *NullableProfileCreateRequestDataAttributes) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableProfileCreateRequestDataAttributes(val *ProfileCreateRequestDataAttributes) *NullableProfileCreateRequestDataAttributes {
	return &NullableProfileCreateRequestDataAttributes{value: val, isSet: true}
}

func (v NullableProfileCreateRequestDataAttributes) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableProfileCreateRequestDataAttributes) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}