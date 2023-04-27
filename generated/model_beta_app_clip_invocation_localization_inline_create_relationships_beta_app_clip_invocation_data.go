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

// checks if the BetaAppClipInvocationLocalizationInlineCreateRelationshipsBetaAppClipInvocationData type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &BetaAppClipInvocationLocalizationInlineCreateRelationshipsBetaAppClipInvocationData{}

// BetaAppClipInvocationLocalizationInlineCreateRelationshipsBetaAppClipInvocationData struct for BetaAppClipInvocationLocalizationInlineCreateRelationshipsBetaAppClipInvocationData
type BetaAppClipInvocationLocalizationInlineCreateRelationshipsBetaAppClipInvocationData struct {
	Type string `json:"type"`
	Id   string `json:"id"`
}

// NewBetaAppClipInvocationLocalizationInlineCreateRelationshipsBetaAppClipInvocationData instantiates a new BetaAppClipInvocationLocalizationInlineCreateRelationshipsBetaAppClipInvocationData object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewBetaAppClipInvocationLocalizationInlineCreateRelationshipsBetaAppClipInvocationData(type_ string, id string) *BetaAppClipInvocationLocalizationInlineCreateRelationshipsBetaAppClipInvocationData {
	this := BetaAppClipInvocationLocalizationInlineCreateRelationshipsBetaAppClipInvocationData{}
	this.Type = type_
	this.Id = id
	return &this
}

// NewBetaAppClipInvocationLocalizationInlineCreateRelationshipsBetaAppClipInvocationDataWithDefaults instantiates a new BetaAppClipInvocationLocalizationInlineCreateRelationshipsBetaAppClipInvocationData object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewBetaAppClipInvocationLocalizationInlineCreateRelationshipsBetaAppClipInvocationDataWithDefaults() *BetaAppClipInvocationLocalizationInlineCreateRelationshipsBetaAppClipInvocationData {
	this := BetaAppClipInvocationLocalizationInlineCreateRelationshipsBetaAppClipInvocationData{}
	return &this
}

// GetType returns the Type field value
func (o *BetaAppClipInvocationLocalizationInlineCreateRelationshipsBetaAppClipInvocationData) GetType() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Type
}

// GetTypeOk returns a tuple with the Type field value
// and a boolean to check if the value has been set.
func (o *BetaAppClipInvocationLocalizationInlineCreateRelationshipsBetaAppClipInvocationData) GetTypeOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Type, true
}

// SetType sets field value
func (o *BetaAppClipInvocationLocalizationInlineCreateRelationshipsBetaAppClipInvocationData) SetType(v string) {
	o.Type = v
}

// GetId returns the Id field value
func (o *BetaAppClipInvocationLocalizationInlineCreateRelationshipsBetaAppClipInvocationData) GetId() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Id
}

// GetIdOk returns a tuple with the Id field value
// and a boolean to check if the value has been set.
func (o *BetaAppClipInvocationLocalizationInlineCreateRelationshipsBetaAppClipInvocationData) GetIdOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Id, true
}

// SetId sets field value
func (o *BetaAppClipInvocationLocalizationInlineCreateRelationshipsBetaAppClipInvocationData) SetId(v string) {
	o.Id = v
}

func (o BetaAppClipInvocationLocalizationInlineCreateRelationshipsBetaAppClipInvocationData) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o BetaAppClipInvocationLocalizationInlineCreateRelationshipsBetaAppClipInvocationData) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["type"] = o.Type
	toSerialize["id"] = o.Id
	return toSerialize, nil
}

type NullableBetaAppClipInvocationLocalizationInlineCreateRelationshipsBetaAppClipInvocationData struct {
	value *BetaAppClipInvocationLocalizationInlineCreateRelationshipsBetaAppClipInvocationData
	isSet bool
}

func (v NullableBetaAppClipInvocationLocalizationInlineCreateRelationshipsBetaAppClipInvocationData) Get() *BetaAppClipInvocationLocalizationInlineCreateRelationshipsBetaAppClipInvocationData {
	return v.value
}

func (v *NullableBetaAppClipInvocationLocalizationInlineCreateRelationshipsBetaAppClipInvocationData) Set(val *BetaAppClipInvocationLocalizationInlineCreateRelationshipsBetaAppClipInvocationData) {
	v.value = val
	v.isSet = true
}

func (v NullableBetaAppClipInvocationLocalizationInlineCreateRelationshipsBetaAppClipInvocationData) IsSet() bool {
	return v.isSet
}

func (v *NullableBetaAppClipInvocationLocalizationInlineCreateRelationshipsBetaAppClipInvocationData) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableBetaAppClipInvocationLocalizationInlineCreateRelationshipsBetaAppClipInvocationData(val *BetaAppClipInvocationLocalizationInlineCreateRelationshipsBetaAppClipInvocationData) *NullableBetaAppClipInvocationLocalizationInlineCreateRelationshipsBetaAppClipInvocationData {
	return &NullableBetaAppClipInvocationLocalizationInlineCreateRelationshipsBetaAppClipInvocationData{value: val, isSet: true}
}

func (v NullableBetaAppClipInvocationLocalizationInlineCreateRelationshipsBetaAppClipInvocationData) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableBetaAppClipInvocationLocalizationInlineCreateRelationshipsBetaAppClipInvocationData) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}