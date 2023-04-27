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

// checks if the SubscriptionGroupCreateRequestData type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &SubscriptionGroupCreateRequestData{}

// SubscriptionGroupCreateRequestData struct for SubscriptionGroupCreateRequestData
type SubscriptionGroupCreateRequestData struct {
	Type          string                                       `json:"type"`
	Attributes    SubscriptionGroupCreateRequestDataAttributes `json:"attributes"`
	Relationships AppEventCreateRequestDataRelationships       `json:"relationships"`
}

// NewSubscriptionGroupCreateRequestData instantiates a new SubscriptionGroupCreateRequestData object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewSubscriptionGroupCreateRequestData(type_ string, attributes SubscriptionGroupCreateRequestDataAttributes, relationships AppEventCreateRequestDataRelationships) *SubscriptionGroupCreateRequestData {
	this := SubscriptionGroupCreateRequestData{}
	this.Type = type_
	this.Attributes = attributes
	this.Relationships = relationships
	return &this
}

// NewSubscriptionGroupCreateRequestDataWithDefaults instantiates a new SubscriptionGroupCreateRequestData object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewSubscriptionGroupCreateRequestDataWithDefaults() *SubscriptionGroupCreateRequestData {
	this := SubscriptionGroupCreateRequestData{}
	return &this
}

// GetType returns the Type field value
func (o *SubscriptionGroupCreateRequestData) GetType() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Type
}

// GetTypeOk returns a tuple with the Type field value
// and a boolean to check if the value has been set.
func (o *SubscriptionGroupCreateRequestData) GetTypeOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Type, true
}

// SetType sets field value
func (o *SubscriptionGroupCreateRequestData) SetType(v string) {
	o.Type = v
}

// GetAttributes returns the Attributes field value
func (o *SubscriptionGroupCreateRequestData) GetAttributes() SubscriptionGroupCreateRequestDataAttributes {
	if o == nil {
		var ret SubscriptionGroupCreateRequestDataAttributes
		return ret
	}

	return o.Attributes
}

// GetAttributesOk returns a tuple with the Attributes field value
// and a boolean to check if the value has been set.
func (o *SubscriptionGroupCreateRequestData) GetAttributesOk() (*SubscriptionGroupCreateRequestDataAttributes, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Attributes, true
}

// SetAttributes sets field value
func (o *SubscriptionGroupCreateRequestData) SetAttributes(v SubscriptionGroupCreateRequestDataAttributes) {
	o.Attributes = v
}

// GetRelationships returns the Relationships field value
func (o *SubscriptionGroupCreateRequestData) GetRelationships() AppEventCreateRequestDataRelationships {
	if o == nil {
		var ret AppEventCreateRequestDataRelationships
		return ret
	}

	return o.Relationships
}

// GetRelationshipsOk returns a tuple with the Relationships field value
// and a boolean to check if the value has been set.
func (o *SubscriptionGroupCreateRequestData) GetRelationshipsOk() (*AppEventCreateRequestDataRelationships, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Relationships, true
}

// SetRelationships sets field value
func (o *SubscriptionGroupCreateRequestData) SetRelationships(v AppEventCreateRequestDataRelationships) {
	o.Relationships = v
}

func (o SubscriptionGroupCreateRequestData) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o SubscriptionGroupCreateRequestData) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["type"] = o.Type
	toSerialize["attributes"] = o.Attributes
	toSerialize["relationships"] = o.Relationships
	return toSerialize, nil
}

type NullableSubscriptionGroupCreateRequestData struct {
	value *SubscriptionGroupCreateRequestData
	isSet bool
}

func (v NullableSubscriptionGroupCreateRequestData) Get() *SubscriptionGroupCreateRequestData {
	return v.value
}

func (v *NullableSubscriptionGroupCreateRequestData) Set(val *SubscriptionGroupCreateRequestData) {
	v.value = val
	v.isSet = true
}

func (v NullableSubscriptionGroupCreateRequestData) IsSet() bool {
	return v.isSet
}

func (v *NullableSubscriptionGroupCreateRequestData) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableSubscriptionGroupCreateRequestData(val *SubscriptionGroupCreateRequestData) *NullableSubscriptionGroupCreateRequestData {
	return &NullableSubscriptionGroupCreateRequestData{value: val, isSet: true}
}

func (v NullableSubscriptionGroupCreateRequestData) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableSubscriptionGroupCreateRequestData) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
