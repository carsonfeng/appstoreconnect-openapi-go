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

// checks if the AppClipAdvancedExperienceRelationshipsAppClip type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &AppClipAdvancedExperienceRelationshipsAppClip{}

// AppClipAdvancedExperienceRelationshipsAppClip struct for AppClipAdvancedExperienceRelationshipsAppClip
type AppClipAdvancedExperienceRelationshipsAppClip struct {
	Links *AppAvailabilityRelationshipsAppLinks              `json:"links,omitempty"`
	Data  *AppClipAdvancedExperienceRelationshipsAppClipData `json:"data,omitempty"`
}

// NewAppClipAdvancedExperienceRelationshipsAppClip instantiates a new AppClipAdvancedExperienceRelationshipsAppClip object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewAppClipAdvancedExperienceRelationshipsAppClip() *AppClipAdvancedExperienceRelationshipsAppClip {
	this := AppClipAdvancedExperienceRelationshipsAppClip{}
	return &this
}

// NewAppClipAdvancedExperienceRelationshipsAppClipWithDefaults instantiates a new AppClipAdvancedExperienceRelationshipsAppClip object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAppClipAdvancedExperienceRelationshipsAppClipWithDefaults() *AppClipAdvancedExperienceRelationshipsAppClip {
	this := AppClipAdvancedExperienceRelationshipsAppClip{}
	return &this
}

// GetLinks returns the Links field value if set, zero value otherwise.
func (o *AppClipAdvancedExperienceRelationshipsAppClip) GetLinks() AppAvailabilityRelationshipsAppLinks {
	if o == nil || IsNil(o.Links) {
		var ret AppAvailabilityRelationshipsAppLinks
		return ret
	}
	return *o.Links
}

// GetLinksOk returns a tuple with the Links field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AppClipAdvancedExperienceRelationshipsAppClip) GetLinksOk() (*AppAvailabilityRelationshipsAppLinks, bool) {
	if o == nil || IsNil(o.Links) {
		return nil, false
	}
	return o.Links, true
}

// HasLinks returns a boolean if a field has been set.
func (o *AppClipAdvancedExperienceRelationshipsAppClip) HasLinks() bool {
	if o != nil && !IsNil(o.Links) {
		return true
	}

	return false
}

// SetLinks gets a reference to the given AppAvailabilityRelationshipsAppLinks and assigns it to the Links field.
func (o *AppClipAdvancedExperienceRelationshipsAppClip) SetLinks(v AppAvailabilityRelationshipsAppLinks) {
	o.Links = &v
}

// GetData returns the Data field value if set, zero value otherwise.
func (o *AppClipAdvancedExperienceRelationshipsAppClip) GetData() AppClipAdvancedExperienceRelationshipsAppClipData {
	if o == nil || IsNil(o.Data) {
		var ret AppClipAdvancedExperienceRelationshipsAppClipData
		return ret
	}
	return *o.Data
}

// GetDataOk returns a tuple with the Data field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AppClipAdvancedExperienceRelationshipsAppClip) GetDataOk() (*AppClipAdvancedExperienceRelationshipsAppClipData, bool) {
	if o == nil || IsNil(o.Data) {
		return nil, false
	}
	return o.Data, true
}

// HasData returns a boolean if a field has been set.
func (o *AppClipAdvancedExperienceRelationshipsAppClip) HasData() bool {
	if o != nil && !IsNil(o.Data) {
		return true
	}

	return false
}

// SetData gets a reference to the given AppClipAdvancedExperienceRelationshipsAppClipData and assigns it to the Data field.
func (o *AppClipAdvancedExperienceRelationshipsAppClip) SetData(v AppClipAdvancedExperienceRelationshipsAppClipData) {
	o.Data = &v
}

func (o AppClipAdvancedExperienceRelationshipsAppClip) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o AppClipAdvancedExperienceRelationshipsAppClip) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.Links) {
		toSerialize["links"] = o.Links
	}
	if !IsNil(o.Data) {
		toSerialize["data"] = o.Data
	}
	return toSerialize, nil
}

type NullableAppClipAdvancedExperienceRelationshipsAppClip struct {
	value *AppClipAdvancedExperienceRelationshipsAppClip
	isSet bool
}

func (v NullableAppClipAdvancedExperienceRelationshipsAppClip) Get() *AppClipAdvancedExperienceRelationshipsAppClip {
	return v.value
}

func (v *NullableAppClipAdvancedExperienceRelationshipsAppClip) Set(val *AppClipAdvancedExperienceRelationshipsAppClip) {
	v.value = val
	v.isSet = true
}

func (v NullableAppClipAdvancedExperienceRelationshipsAppClip) IsSet() bool {
	return v.isSet
}

func (v *NullableAppClipAdvancedExperienceRelationshipsAppClip) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableAppClipAdvancedExperienceRelationshipsAppClip(val *AppClipAdvancedExperienceRelationshipsAppClip) *NullableAppClipAdvancedExperienceRelationshipsAppClip {
	return &NullableAppClipAdvancedExperienceRelationshipsAppClip{value: val, isSet: true}
}

func (v NullableAppClipAdvancedExperienceRelationshipsAppClip) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableAppClipAdvancedExperienceRelationshipsAppClip) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}