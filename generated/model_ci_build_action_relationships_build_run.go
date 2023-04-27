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

// checks if the CiBuildActionRelationshipsBuildRun type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &CiBuildActionRelationshipsBuildRun{}

// CiBuildActionRelationshipsBuildRun struct for CiBuildActionRelationshipsBuildRun
type CiBuildActionRelationshipsBuildRun struct {
	Links *AppAvailabilityRelationshipsAppLinks   `json:"links,omitempty"`
	Data  *CiBuildActionRelationshipsBuildRunData `json:"data,omitempty"`
}

// NewCiBuildActionRelationshipsBuildRun instantiates a new CiBuildActionRelationshipsBuildRun object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewCiBuildActionRelationshipsBuildRun() *CiBuildActionRelationshipsBuildRun {
	this := CiBuildActionRelationshipsBuildRun{}
	return &this
}

// NewCiBuildActionRelationshipsBuildRunWithDefaults instantiates a new CiBuildActionRelationshipsBuildRun object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewCiBuildActionRelationshipsBuildRunWithDefaults() *CiBuildActionRelationshipsBuildRun {
	this := CiBuildActionRelationshipsBuildRun{}
	return &this
}

// GetLinks returns the Links field value if set, zero value otherwise.
func (o *CiBuildActionRelationshipsBuildRun) GetLinks() AppAvailabilityRelationshipsAppLinks {
	if o == nil || IsNil(o.Links) {
		var ret AppAvailabilityRelationshipsAppLinks
		return ret
	}
	return *o.Links
}

// GetLinksOk returns a tuple with the Links field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CiBuildActionRelationshipsBuildRun) GetLinksOk() (*AppAvailabilityRelationshipsAppLinks, bool) {
	if o == nil || IsNil(o.Links) {
		return nil, false
	}
	return o.Links, true
}

// HasLinks returns a boolean if a field has been set.
func (o *CiBuildActionRelationshipsBuildRun) HasLinks() bool {
	if o != nil && !IsNil(o.Links) {
		return true
	}

	return false
}

// SetLinks gets a reference to the given AppAvailabilityRelationshipsAppLinks and assigns it to the Links field.
func (o *CiBuildActionRelationshipsBuildRun) SetLinks(v AppAvailabilityRelationshipsAppLinks) {
	o.Links = &v
}

// GetData returns the Data field value if set, zero value otherwise.
func (o *CiBuildActionRelationshipsBuildRun) GetData() CiBuildActionRelationshipsBuildRunData {
	if o == nil || IsNil(o.Data) {
		var ret CiBuildActionRelationshipsBuildRunData
		return ret
	}
	return *o.Data
}

// GetDataOk returns a tuple with the Data field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CiBuildActionRelationshipsBuildRun) GetDataOk() (*CiBuildActionRelationshipsBuildRunData, bool) {
	if o == nil || IsNil(o.Data) {
		return nil, false
	}
	return o.Data, true
}

// HasData returns a boolean if a field has been set.
func (o *CiBuildActionRelationshipsBuildRun) HasData() bool {
	if o != nil && !IsNil(o.Data) {
		return true
	}

	return false
}

// SetData gets a reference to the given CiBuildActionRelationshipsBuildRunData and assigns it to the Data field.
func (o *CiBuildActionRelationshipsBuildRun) SetData(v CiBuildActionRelationshipsBuildRunData) {
	o.Data = &v
}

func (o CiBuildActionRelationshipsBuildRun) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o CiBuildActionRelationshipsBuildRun) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.Links) {
		toSerialize["links"] = o.Links
	}
	if !IsNil(o.Data) {
		toSerialize["data"] = o.Data
	}
	return toSerialize, nil
}

type NullableCiBuildActionRelationshipsBuildRun struct {
	value *CiBuildActionRelationshipsBuildRun
	isSet bool
}

func (v NullableCiBuildActionRelationshipsBuildRun) Get() *CiBuildActionRelationshipsBuildRun {
	return v.value
}

func (v *NullableCiBuildActionRelationshipsBuildRun) Set(val *CiBuildActionRelationshipsBuildRun) {
	v.value = val
	v.isSet = true
}

func (v NullableCiBuildActionRelationshipsBuildRun) IsSet() bool {
	return v.isSet
}

func (v *NullableCiBuildActionRelationshipsBuildRun) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableCiBuildActionRelationshipsBuildRun(val *CiBuildActionRelationshipsBuildRun) *NullableCiBuildActionRelationshipsBuildRun {
	return &NullableCiBuildActionRelationshipsBuildRun{value: val, isSet: true}
}

func (v NullableCiBuildActionRelationshipsBuildRun) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableCiBuildActionRelationshipsBuildRun) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
