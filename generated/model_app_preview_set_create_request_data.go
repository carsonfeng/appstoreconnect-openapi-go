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

// checks if the AppPreviewSetCreateRequestData type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &AppPreviewSetCreateRequestData{}

// AppPreviewSetCreateRequestData struct for AppPreviewSetCreateRequestData
type AppPreviewSetCreateRequestData struct {
	Type          string                                       `json:"type"`
	Attributes    AppPreviewSetCreateRequestDataAttributes     `json:"attributes"`
	Relationships *AppPreviewSetCreateRequestDataRelationships `json:"relationships,omitempty"`
}

// NewAppPreviewSetCreateRequestData instantiates a new AppPreviewSetCreateRequestData object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewAppPreviewSetCreateRequestData(type_ string, attributes AppPreviewSetCreateRequestDataAttributes) *AppPreviewSetCreateRequestData {
	this := AppPreviewSetCreateRequestData{}
	this.Type = type_
	this.Attributes = attributes
	return &this
}

// NewAppPreviewSetCreateRequestDataWithDefaults instantiates a new AppPreviewSetCreateRequestData object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAppPreviewSetCreateRequestDataWithDefaults() *AppPreviewSetCreateRequestData {
	this := AppPreviewSetCreateRequestData{}
	return &this
}

// GetType returns the Type field value
func (o *AppPreviewSetCreateRequestData) GetType() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Type
}

// GetTypeOk returns a tuple with the Type field value
// and a boolean to check if the value has been set.
func (o *AppPreviewSetCreateRequestData) GetTypeOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Type, true
}

// SetType sets field value
func (o *AppPreviewSetCreateRequestData) SetType(v string) {
	o.Type = v
}

// GetAttributes returns the Attributes field value
func (o *AppPreviewSetCreateRequestData) GetAttributes() AppPreviewSetCreateRequestDataAttributes {
	if o == nil {
		var ret AppPreviewSetCreateRequestDataAttributes
		return ret
	}

	return o.Attributes
}

// GetAttributesOk returns a tuple with the Attributes field value
// and a boolean to check if the value has been set.
func (o *AppPreviewSetCreateRequestData) GetAttributesOk() (*AppPreviewSetCreateRequestDataAttributes, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Attributes, true
}

// SetAttributes sets field value
func (o *AppPreviewSetCreateRequestData) SetAttributes(v AppPreviewSetCreateRequestDataAttributes) {
	o.Attributes = v
}

// GetRelationships returns the Relationships field value if set, zero value otherwise.
func (o *AppPreviewSetCreateRequestData) GetRelationships() AppPreviewSetCreateRequestDataRelationships {
	if o == nil || IsNil(o.Relationships) {
		var ret AppPreviewSetCreateRequestDataRelationships
		return ret
	}
	return *o.Relationships
}

// GetRelationshipsOk returns a tuple with the Relationships field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AppPreviewSetCreateRequestData) GetRelationshipsOk() (*AppPreviewSetCreateRequestDataRelationships, bool) {
	if o == nil || IsNil(o.Relationships) {
		return nil, false
	}
	return o.Relationships, true
}

// HasRelationships returns a boolean if a field has been set.
func (o *AppPreviewSetCreateRequestData) HasRelationships() bool {
	if o != nil && !IsNil(o.Relationships) {
		return true
	}

	return false
}

// SetRelationships gets a reference to the given AppPreviewSetCreateRequestDataRelationships and assigns it to the Relationships field.
func (o *AppPreviewSetCreateRequestData) SetRelationships(v AppPreviewSetCreateRequestDataRelationships) {
	o.Relationships = &v
}

func (o AppPreviewSetCreateRequestData) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o AppPreviewSetCreateRequestData) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["type"] = o.Type
	toSerialize["attributes"] = o.Attributes
	if !IsNil(o.Relationships) {
		toSerialize["relationships"] = o.Relationships
	}
	return toSerialize, nil
}

type NullableAppPreviewSetCreateRequestData struct {
	value *AppPreviewSetCreateRequestData
	isSet bool
}

func (v NullableAppPreviewSetCreateRequestData) Get() *AppPreviewSetCreateRequestData {
	return v.value
}

func (v *NullableAppPreviewSetCreateRequestData) Set(val *AppPreviewSetCreateRequestData) {
	v.value = val
	v.isSet = true
}

func (v NullableAppPreviewSetCreateRequestData) IsSet() bool {
	return v.isSet
}

func (v *NullableAppPreviewSetCreateRequestData) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableAppPreviewSetCreateRequestData(val *AppPreviewSetCreateRequestData) *NullableAppPreviewSetCreateRequestData {
	return &NullableAppPreviewSetCreateRequestData{value: val, isSet: true}
}

func (v NullableAppPreviewSetCreateRequestData) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableAppPreviewSetCreateRequestData) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
