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

// checks if the ProfileCreateRequestData type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &ProfileCreateRequestData{}

// ProfileCreateRequestData struct for ProfileCreateRequestData
type ProfileCreateRequestData struct {
	Type          string                                `json:"type"`
	Attributes    ProfileCreateRequestDataAttributes    `json:"attributes"`
	Relationships ProfileCreateRequestDataRelationships `json:"relationships"`
}

// NewProfileCreateRequestData instantiates a new ProfileCreateRequestData object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewProfileCreateRequestData(type_ string, attributes ProfileCreateRequestDataAttributes, relationships ProfileCreateRequestDataRelationships) *ProfileCreateRequestData {
	this := ProfileCreateRequestData{}
	this.Type = type_
	this.Attributes = attributes
	this.Relationships = relationships
	return &this
}

// NewProfileCreateRequestDataWithDefaults instantiates a new ProfileCreateRequestData object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewProfileCreateRequestDataWithDefaults() *ProfileCreateRequestData {
	this := ProfileCreateRequestData{}
	return &this
}

// GetType returns the Type field value
func (o *ProfileCreateRequestData) GetType() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Type
}

// GetTypeOk returns a tuple with the Type field value
// and a boolean to check if the value has been set.
func (o *ProfileCreateRequestData) GetTypeOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Type, true
}

// SetType sets field value
func (o *ProfileCreateRequestData) SetType(v string) {
	o.Type = v
}

// GetAttributes returns the Attributes field value
func (o *ProfileCreateRequestData) GetAttributes() ProfileCreateRequestDataAttributes {
	if o == nil {
		var ret ProfileCreateRequestDataAttributes
		return ret
	}

	return o.Attributes
}

// GetAttributesOk returns a tuple with the Attributes field value
// and a boolean to check if the value has been set.
func (o *ProfileCreateRequestData) GetAttributesOk() (*ProfileCreateRequestDataAttributes, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Attributes, true
}

// SetAttributes sets field value
func (o *ProfileCreateRequestData) SetAttributes(v ProfileCreateRequestDataAttributes) {
	o.Attributes = v
}

// GetRelationships returns the Relationships field value
func (o *ProfileCreateRequestData) GetRelationships() ProfileCreateRequestDataRelationships {
	if o == nil {
		var ret ProfileCreateRequestDataRelationships
		return ret
	}

	return o.Relationships
}

// GetRelationshipsOk returns a tuple with the Relationships field value
// and a boolean to check if the value has been set.
func (o *ProfileCreateRequestData) GetRelationshipsOk() (*ProfileCreateRequestDataRelationships, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Relationships, true
}

// SetRelationships sets field value
func (o *ProfileCreateRequestData) SetRelationships(v ProfileCreateRequestDataRelationships) {
	o.Relationships = v
}

func (o ProfileCreateRequestData) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o ProfileCreateRequestData) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["type"] = o.Type
	toSerialize["attributes"] = o.Attributes
	toSerialize["relationships"] = o.Relationships
	return toSerialize, nil
}

type NullableProfileCreateRequestData struct {
	value *ProfileCreateRequestData
	isSet bool
}

func (v NullableProfileCreateRequestData) Get() *ProfileCreateRequestData {
	return v.value
}

func (v *NullableProfileCreateRequestData) Set(val *ProfileCreateRequestData) {
	v.value = val
	v.isSet = true
}

func (v NullableProfileCreateRequestData) IsSet() bool {
	return v.isSet
}

func (v *NullableProfileCreateRequestData) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableProfileCreateRequestData(val *ProfileCreateRequestData) *NullableProfileCreateRequestData {
	return &NullableProfileCreateRequestData{value: val, isSet: true}
}

func (v NullableProfileCreateRequestData) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableProfileCreateRequestData) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
