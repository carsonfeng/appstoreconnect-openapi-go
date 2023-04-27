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

// checks if the AppStoreVersionRelationshipsRoutingAppCoverage type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &AppStoreVersionRelationshipsRoutingAppCoverage{}

// AppStoreVersionRelationshipsRoutingAppCoverage struct for AppStoreVersionRelationshipsRoutingAppCoverage
type AppStoreVersionRelationshipsRoutingAppCoverage struct {
	Links *AppAvailabilityRelationshipsAppLinks               `json:"links,omitempty"`
	Data  *AppStoreVersionRelationshipsRoutingAppCoverageData `json:"data,omitempty"`
}

// NewAppStoreVersionRelationshipsRoutingAppCoverage instantiates a new AppStoreVersionRelationshipsRoutingAppCoverage object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewAppStoreVersionRelationshipsRoutingAppCoverage() *AppStoreVersionRelationshipsRoutingAppCoverage {
	this := AppStoreVersionRelationshipsRoutingAppCoverage{}
	return &this
}

// NewAppStoreVersionRelationshipsRoutingAppCoverageWithDefaults instantiates a new AppStoreVersionRelationshipsRoutingAppCoverage object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAppStoreVersionRelationshipsRoutingAppCoverageWithDefaults() *AppStoreVersionRelationshipsRoutingAppCoverage {
	this := AppStoreVersionRelationshipsRoutingAppCoverage{}
	return &this
}

// GetLinks returns the Links field value if set, zero value otherwise.
func (o *AppStoreVersionRelationshipsRoutingAppCoverage) GetLinks() AppAvailabilityRelationshipsAppLinks {
	if o == nil || IsNil(o.Links) {
		var ret AppAvailabilityRelationshipsAppLinks
		return ret
	}
	return *o.Links
}

// GetLinksOk returns a tuple with the Links field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AppStoreVersionRelationshipsRoutingAppCoverage) GetLinksOk() (*AppAvailabilityRelationshipsAppLinks, bool) {
	if o == nil || IsNil(o.Links) {
		return nil, false
	}
	return o.Links, true
}

// HasLinks returns a boolean if a field has been set.
func (o *AppStoreVersionRelationshipsRoutingAppCoverage) HasLinks() bool {
	if o != nil && !IsNil(o.Links) {
		return true
	}

	return false
}

// SetLinks gets a reference to the given AppAvailabilityRelationshipsAppLinks and assigns it to the Links field.
func (o *AppStoreVersionRelationshipsRoutingAppCoverage) SetLinks(v AppAvailabilityRelationshipsAppLinks) {
	o.Links = &v
}

// GetData returns the Data field value if set, zero value otherwise.
func (o *AppStoreVersionRelationshipsRoutingAppCoverage) GetData() AppStoreVersionRelationshipsRoutingAppCoverageData {
	if o == nil || IsNil(o.Data) {
		var ret AppStoreVersionRelationshipsRoutingAppCoverageData
		return ret
	}
	return *o.Data
}

// GetDataOk returns a tuple with the Data field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AppStoreVersionRelationshipsRoutingAppCoverage) GetDataOk() (*AppStoreVersionRelationshipsRoutingAppCoverageData, bool) {
	if o == nil || IsNil(o.Data) {
		return nil, false
	}
	return o.Data, true
}

// HasData returns a boolean if a field has been set.
func (o *AppStoreVersionRelationshipsRoutingAppCoverage) HasData() bool {
	if o != nil && !IsNil(o.Data) {
		return true
	}

	return false
}

// SetData gets a reference to the given AppStoreVersionRelationshipsRoutingAppCoverageData and assigns it to the Data field.
func (o *AppStoreVersionRelationshipsRoutingAppCoverage) SetData(v AppStoreVersionRelationshipsRoutingAppCoverageData) {
	o.Data = &v
}

func (o AppStoreVersionRelationshipsRoutingAppCoverage) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o AppStoreVersionRelationshipsRoutingAppCoverage) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.Links) {
		toSerialize["links"] = o.Links
	}
	if !IsNil(o.Data) {
		toSerialize["data"] = o.Data
	}
	return toSerialize, nil
}

type NullableAppStoreVersionRelationshipsRoutingAppCoverage struct {
	value *AppStoreVersionRelationshipsRoutingAppCoverage
	isSet bool
}

func (v NullableAppStoreVersionRelationshipsRoutingAppCoverage) Get() *AppStoreVersionRelationshipsRoutingAppCoverage {
	return v.value
}

func (v *NullableAppStoreVersionRelationshipsRoutingAppCoverage) Set(val *AppStoreVersionRelationshipsRoutingAppCoverage) {
	v.value = val
	v.isSet = true
}

func (v NullableAppStoreVersionRelationshipsRoutingAppCoverage) IsSet() bool {
	return v.isSet
}

func (v *NullableAppStoreVersionRelationshipsRoutingAppCoverage) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableAppStoreVersionRelationshipsRoutingAppCoverage(val *AppStoreVersionRelationshipsRoutingAppCoverage) *NullableAppStoreVersionRelationshipsRoutingAppCoverage {
	return &NullableAppStoreVersionRelationshipsRoutingAppCoverage{value: val, isSet: true}
}

func (v NullableAppStoreVersionRelationshipsRoutingAppCoverage) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableAppStoreVersionRelationshipsRoutingAppCoverage) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}