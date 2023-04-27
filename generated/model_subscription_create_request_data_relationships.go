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

// checks if the SubscriptionCreateRequestDataRelationships type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &SubscriptionCreateRequestDataRelationships{}

// SubscriptionCreateRequestDataRelationships struct for SubscriptionCreateRequestDataRelationships
type SubscriptionCreateRequestDataRelationships struct {
	Group SubscriptionGroupLocalizationCreateRequestDataRelationshipsSubscriptionGroup `json:"group"`
}

// NewSubscriptionCreateRequestDataRelationships instantiates a new SubscriptionCreateRequestDataRelationships object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewSubscriptionCreateRequestDataRelationships(group SubscriptionGroupLocalizationCreateRequestDataRelationshipsSubscriptionGroup) *SubscriptionCreateRequestDataRelationships {
	this := SubscriptionCreateRequestDataRelationships{}
	this.Group = group
	return &this
}

// NewSubscriptionCreateRequestDataRelationshipsWithDefaults instantiates a new SubscriptionCreateRequestDataRelationships object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewSubscriptionCreateRequestDataRelationshipsWithDefaults() *SubscriptionCreateRequestDataRelationships {
	this := SubscriptionCreateRequestDataRelationships{}
	return &this
}

// GetGroup returns the Group field value
func (o *SubscriptionCreateRequestDataRelationships) GetGroup() SubscriptionGroupLocalizationCreateRequestDataRelationshipsSubscriptionGroup {
	if o == nil {
		var ret SubscriptionGroupLocalizationCreateRequestDataRelationshipsSubscriptionGroup
		return ret
	}

	return o.Group
}

// GetGroupOk returns a tuple with the Group field value
// and a boolean to check if the value has been set.
func (o *SubscriptionCreateRequestDataRelationships) GetGroupOk() (*SubscriptionGroupLocalizationCreateRequestDataRelationshipsSubscriptionGroup, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Group, true
}

// SetGroup sets field value
func (o *SubscriptionCreateRequestDataRelationships) SetGroup(v SubscriptionGroupLocalizationCreateRequestDataRelationshipsSubscriptionGroup) {
	o.Group = v
}

func (o SubscriptionCreateRequestDataRelationships) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o SubscriptionCreateRequestDataRelationships) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["group"] = o.Group
	return toSerialize, nil
}

type NullableSubscriptionCreateRequestDataRelationships struct {
	value *SubscriptionCreateRequestDataRelationships
	isSet bool
}

func (v NullableSubscriptionCreateRequestDataRelationships) Get() *SubscriptionCreateRequestDataRelationships {
	return v.value
}

func (v *NullableSubscriptionCreateRequestDataRelationships) Set(val *SubscriptionCreateRequestDataRelationships) {
	v.value = val
	v.isSet = true
}

func (v NullableSubscriptionCreateRequestDataRelationships) IsSet() bool {
	return v.isSet
}

func (v *NullableSubscriptionCreateRequestDataRelationships) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableSubscriptionCreateRequestDataRelationships(val *SubscriptionCreateRequestDataRelationships) *NullableSubscriptionCreateRequestDataRelationships {
	return &NullableSubscriptionCreateRequestDataRelationships{value: val, isSet: true}
}

func (v NullableSubscriptionCreateRequestDataRelationships) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableSubscriptionCreateRequestDataRelationships) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
