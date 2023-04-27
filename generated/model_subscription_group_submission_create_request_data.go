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

// checks if the SubscriptionGroupSubmissionCreateRequestData type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &SubscriptionGroupSubmissionCreateRequestData{}

// SubscriptionGroupSubmissionCreateRequestData struct for SubscriptionGroupSubmissionCreateRequestData
type SubscriptionGroupSubmissionCreateRequestData struct {
	Type          string                                                      `json:"type"`
	Relationships SubscriptionGroupLocalizationCreateRequestDataRelationships `json:"relationships"`
}

// NewSubscriptionGroupSubmissionCreateRequestData instantiates a new SubscriptionGroupSubmissionCreateRequestData object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewSubscriptionGroupSubmissionCreateRequestData(type_ string, relationships SubscriptionGroupLocalizationCreateRequestDataRelationships) *SubscriptionGroupSubmissionCreateRequestData {
	this := SubscriptionGroupSubmissionCreateRequestData{}
	this.Type = type_
	this.Relationships = relationships
	return &this
}

// NewSubscriptionGroupSubmissionCreateRequestDataWithDefaults instantiates a new SubscriptionGroupSubmissionCreateRequestData object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewSubscriptionGroupSubmissionCreateRequestDataWithDefaults() *SubscriptionGroupSubmissionCreateRequestData {
	this := SubscriptionGroupSubmissionCreateRequestData{}
	return &this
}

// GetType returns the Type field value
func (o *SubscriptionGroupSubmissionCreateRequestData) GetType() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Type
}

// GetTypeOk returns a tuple with the Type field value
// and a boolean to check if the value has been set.
func (o *SubscriptionGroupSubmissionCreateRequestData) GetTypeOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Type, true
}

// SetType sets field value
func (o *SubscriptionGroupSubmissionCreateRequestData) SetType(v string) {
	o.Type = v
}

// GetRelationships returns the Relationships field value
func (o *SubscriptionGroupSubmissionCreateRequestData) GetRelationships() SubscriptionGroupLocalizationCreateRequestDataRelationships {
	if o == nil {
		var ret SubscriptionGroupLocalizationCreateRequestDataRelationships
		return ret
	}

	return o.Relationships
}

// GetRelationshipsOk returns a tuple with the Relationships field value
// and a boolean to check if the value has been set.
func (o *SubscriptionGroupSubmissionCreateRequestData) GetRelationshipsOk() (*SubscriptionGroupLocalizationCreateRequestDataRelationships, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Relationships, true
}

// SetRelationships sets field value
func (o *SubscriptionGroupSubmissionCreateRequestData) SetRelationships(v SubscriptionGroupLocalizationCreateRequestDataRelationships) {
	o.Relationships = v
}

func (o SubscriptionGroupSubmissionCreateRequestData) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o SubscriptionGroupSubmissionCreateRequestData) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["type"] = o.Type
	toSerialize["relationships"] = o.Relationships
	return toSerialize, nil
}

type NullableSubscriptionGroupSubmissionCreateRequestData struct {
	value *SubscriptionGroupSubmissionCreateRequestData
	isSet bool
}

func (v NullableSubscriptionGroupSubmissionCreateRequestData) Get() *SubscriptionGroupSubmissionCreateRequestData {
	return v.value
}

func (v *NullableSubscriptionGroupSubmissionCreateRequestData) Set(val *SubscriptionGroupSubmissionCreateRequestData) {
	v.value = val
	v.isSet = true
}

func (v NullableSubscriptionGroupSubmissionCreateRequestData) IsSet() bool {
	return v.isSet
}

func (v *NullableSubscriptionGroupSubmissionCreateRequestData) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableSubscriptionGroupSubmissionCreateRequestData(val *SubscriptionGroupSubmissionCreateRequestData) *NullableSubscriptionGroupSubmissionCreateRequestData {
	return &NullableSubscriptionGroupSubmissionCreateRequestData{value: val, isSet: true}
}

func (v NullableSubscriptionGroupSubmissionCreateRequestData) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableSubscriptionGroupSubmissionCreateRequestData) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
