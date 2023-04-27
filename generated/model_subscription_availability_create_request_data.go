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

// checks if the SubscriptionAvailabilityCreateRequestData type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &SubscriptionAvailabilityCreateRequestData{}

// SubscriptionAvailabilityCreateRequestData struct for SubscriptionAvailabilityCreateRequestData
type SubscriptionAvailabilityCreateRequestData struct {
	Type          string                                                 `json:"type"`
	Attributes    AppAvailabilityCreateRequestDataAttributes             `json:"attributes"`
	Relationships SubscriptionAvailabilityCreateRequestDataRelationships `json:"relationships"`
}

// NewSubscriptionAvailabilityCreateRequestData instantiates a new SubscriptionAvailabilityCreateRequestData object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewSubscriptionAvailabilityCreateRequestData(type_ string, attributes AppAvailabilityCreateRequestDataAttributes, relationships SubscriptionAvailabilityCreateRequestDataRelationships) *SubscriptionAvailabilityCreateRequestData {
	this := SubscriptionAvailabilityCreateRequestData{}
	this.Type = type_
	this.Attributes = attributes
	this.Relationships = relationships
	return &this
}

// NewSubscriptionAvailabilityCreateRequestDataWithDefaults instantiates a new SubscriptionAvailabilityCreateRequestData object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewSubscriptionAvailabilityCreateRequestDataWithDefaults() *SubscriptionAvailabilityCreateRequestData {
	this := SubscriptionAvailabilityCreateRequestData{}
	return &this
}

// GetType returns the Type field value
func (o *SubscriptionAvailabilityCreateRequestData) GetType() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Type
}

// GetTypeOk returns a tuple with the Type field value
// and a boolean to check if the value has been set.
func (o *SubscriptionAvailabilityCreateRequestData) GetTypeOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Type, true
}

// SetType sets field value
func (o *SubscriptionAvailabilityCreateRequestData) SetType(v string) {
	o.Type = v
}

// GetAttributes returns the Attributes field value
func (o *SubscriptionAvailabilityCreateRequestData) GetAttributes() AppAvailabilityCreateRequestDataAttributes {
	if o == nil {
		var ret AppAvailabilityCreateRequestDataAttributes
		return ret
	}

	return o.Attributes
}

// GetAttributesOk returns a tuple with the Attributes field value
// and a boolean to check if the value has been set.
func (o *SubscriptionAvailabilityCreateRequestData) GetAttributesOk() (*AppAvailabilityCreateRequestDataAttributes, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Attributes, true
}

// SetAttributes sets field value
func (o *SubscriptionAvailabilityCreateRequestData) SetAttributes(v AppAvailabilityCreateRequestDataAttributes) {
	o.Attributes = v
}

// GetRelationships returns the Relationships field value
func (o *SubscriptionAvailabilityCreateRequestData) GetRelationships() SubscriptionAvailabilityCreateRequestDataRelationships {
	if o == nil {
		var ret SubscriptionAvailabilityCreateRequestDataRelationships
		return ret
	}

	return o.Relationships
}

// GetRelationshipsOk returns a tuple with the Relationships field value
// and a boolean to check if the value has been set.
func (o *SubscriptionAvailabilityCreateRequestData) GetRelationshipsOk() (*SubscriptionAvailabilityCreateRequestDataRelationships, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Relationships, true
}

// SetRelationships sets field value
func (o *SubscriptionAvailabilityCreateRequestData) SetRelationships(v SubscriptionAvailabilityCreateRequestDataRelationships) {
	o.Relationships = v
}

func (o SubscriptionAvailabilityCreateRequestData) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o SubscriptionAvailabilityCreateRequestData) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["type"] = o.Type
	toSerialize["attributes"] = o.Attributes
	toSerialize["relationships"] = o.Relationships
	return toSerialize, nil
}

type NullableSubscriptionAvailabilityCreateRequestData struct {
	value *SubscriptionAvailabilityCreateRequestData
	isSet bool
}

func (v NullableSubscriptionAvailabilityCreateRequestData) Get() *SubscriptionAvailabilityCreateRequestData {
	return v.value
}

func (v *NullableSubscriptionAvailabilityCreateRequestData) Set(val *SubscriptionAvailabilityCreateRequestData) {
	v.value = val
	v.isSet = true
}

func (v NullableSubscriptionAvailabilityCreateRequestData) IsSet() bool {
	return v.isSet
}

func (v *NullableSubscriptionAvailabilityCreateRequestData) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableSubscriptionAvailabilityCreateRequestData(val *SubscriptionAvailabilityCreateRequestData) *NullableSubscriptionAvailabilityCreateRequestData {
	return &NullableSubscriptionAvailabilityCreateRequestData{value: val, isSet: true}
}

func (v NullableSubscriptionAvailabilityCreateRequestData) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableSubscriptionAvailabilityCreateRequestData) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
