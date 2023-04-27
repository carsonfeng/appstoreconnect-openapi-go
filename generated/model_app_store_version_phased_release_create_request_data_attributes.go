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

// checks if the AppStoreVersionPhasedReleaseCreateRequestDataAttributes type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &AppStoreVersionPhasedReleaseCreateRequestDataAttributes{}

// AppStoreVersionPhasedReleaseCreateRequestDataAttributes struct for AppStoreVersionPhasedReleaseCreateRequestDataAttributes
type AppStoreVersionPhasedReleaseCreateRequestDataAttributes struct {
	PhasedReleaseState *PhasedReleaseState `json:"phasedReleaseState,omitempty"`
}

// NewAppStoreVersionPhasedReleaseCreateRequestDataAttributes instantiates a new AppStoreVersionPhasedReleaseCreateRequestDataAttributes object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewAppStoreVersionPhasedReleaseCreateRequestDataAttributes() *AppStoreVersionPhasedReleaseCreateRequestDataAttributes {
	this := AppStoreVersionPhasedReleaseCreateRequestDataAttributes{}
	return &this
}

// NewAppStoreVersionPhasedReleaseCreateRequestDataAttributesWithDefaults instantiates a new AppStoreVersionPhasedReleaseCreateRequestDataAttributes object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAppStoreVersionPhasedReleaseCreateRequestDataAttributesWithDefaults() *AppStoreVersionPhasedReleaseCreateRequestDataAttributes {
	this := AppStoreVersionPhasedReleaseCreateRequestDataAttributes{}
	return &this
}

// GetPhasedReleaseState returns the PhasedReleaseState field value if set, zero value otherwise.
func (o *AppStoreVersionPhasedReleaseCreateRequestDataAttributes) GetPhasedReleaseState() PhasedReleaseState {
	if o == nil || IsNil(o.PhasedReleaseState) {
		var ret PhasedReleaseState
		return ret
	}
	return *o.PhasedReleaseState
}

// GetPhasedReleaseStateOk returns a tuple with the PhasedReleaseState field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AppStoreVersionPhasedReleaseCreateRequestDataAttributes) GetPhasedReleaseStateOk() (*PhasedReleaseState, bool) {
	if o == nil || IsNil(o.PhasedReleaseState) {
		return nil, false
	}
	return o.PhasedReleaseState, true
}

// HasPhasedReleaseState returns a boolean if a field has been set.
func (o *AppStoreVersionPhasedReleaseCreateRequestDataAttributes) HasPhasedReleaseState() bool {
	if o != nil && !IsNil(o.PhasedReleaseState) {
		return true
	}

	return false
}

// SetPhasedReleaseState gets a reference to the given PhasedReleaseState and assigns it to the PhasedReleaseState field.
func (o *AppStoreVersionPhasedReleaseCreateRequestDataAttributes) SetPhasedReleaseState(v PhasedReleaseState) {
	o.PhasedReleaseState = &v
}

func (o AppStoreVersionPhasedReleaseCreateRequestDataAttributes) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o AppStoreVersionPhasedReleaseCreateRequestDataAttributes) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.PhasedReleaseState) {
		toSerialize["phasedReleaseState"] = o.PhasedReleaseState
	}
	return toSerialize, nil
}

type NullableAppStoreVersionPhasedReleaseCreateRequestDataAttributes struct {
	value *AppStoreVersionPhasedReleaseCreateRequestDataAttributes
	isSet bool
}

func (v NullableAppStoreVersionPhasedReleaseCreateRequestDataAttributes) Get() *AppStoreVersionPhasedReleaseCreateRequestDataAttributes {
	return v.value
}

func (v *NullableAppStoreVersionPhasedReleaseCreateRequestDataAttributes) Set(val *AppStoreVersionPhasedReleaseCreateRequestDataAttributes) {
	v.value = val
	v.isSet = true
}

func (v NullableAppStoreVersionPhasedReleaseCreateRequestDataAttributes) IsSet() bool {
	return v.isSet
}

func (v *NullableAppStoreVersionPhasedReleaseCreateRequestDataAttributes) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableAppStoreVersionPhasedReleaseCreateRequestDataAttributes(val *AppStoreVersionPhasedReleaseCreateRequestDataAttributes) *NullableAppStoreVersionPhasedReleaseCreateRequestDataAttributes {
	return &NullableAppStoreVersionPhasedReleaseCreateRequestDataAttributes{value: val, isSet: true}
}

func (v NullableAppStoreVersionPhasedReleaseCreateRequestDataAttributes) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableAppStoreVersionPhasedReleaseCreateRequestDataAttributes) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}