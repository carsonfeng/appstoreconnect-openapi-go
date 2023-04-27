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

// checks if the AppEncryptionDeclarationDocumentUpdateRequestData type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &AppEncryptionDeclarationDocumentUpdateRequestData{}

// AppEncryptionDeclarationDocumentUpdateRequestData struct for AppEncryptionDeclarationDocumentUpdateRequestData
type AppEncryptionDeclarationDocumentUpdateRequestData struct {
	Type       string                                                     `json:"type"`
	Id         string                                                     `json:"id"`
	Attributes *AppClipAdvancedExperienceImageUpdateRequestDataAttributes `json:"attributes,omitempty"`
}

// NewAppEncryptionDeclarationDocumentUpdateRequestData instantiates a new AppEncryptionDeclarationDocumentUpdateRequestData object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewAppEncryptionDeclarationDocumentUpdateRequestData(type_ string, id string) *AppEncryptionDeclarationDocumentUpdateRequestData {
	this := AppEncryptionDeclarationDocumentUpdateRequestData{}
	this.Type = type_
	this.Id = id
	return &this
}

// NewAppEncryptionDeclarationDocumentUpdateRequestDataWithDefaults instantiates a new AppEncryptionDeclarationDocumentUpdateRequestData object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAppEncryptionDeclarationDocumentUpdateRequestDataWithDefaults() *AppEncryptionDeclarationDocumentUpdateRequestData {
	this := AppEncryptionDeclarationDocumentUpdateRequestData{}
	return &this
}

// GetType returns the Type field value
func (o *AppEncryptionDeclarationDocumentUpdateRequestData) GetType() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Type
}

// GetTypeOk returns a tuple with the Type field value
// and a boolean to check if the value has been set.
func (o *AppEncryptionDeclarationDocumentUpdateRequestData) GetTypeOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Type, true
}

// SetType sets field value
func (o *AppEncryptionDeclarationDocumentUpdateRequestData) SetType(v string) {
	o.Type = v
}

// GetId returns the Id field value
func (o *AppEncryptionDeclarationDocumentUpdateRequestData) GetId() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Id
}

// GetIdOk returns a tuple with the Id field value
// and a boolean to check if the value has been set.
func (o *AppEncryptionDeclarationDocumentUpdateRequestData) GetIdOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Id, true
}

// SetId sets field value
func (o *AppEncryptionDeclarationDocumentUpdateRequestData) SetId(v string) {
	o.Id = v
}

// GetAttributes returns the Attributes field value if set, zero value otherwise.
func (o *AppEncryptionDeclarationDocumentUpdateRequestData) GetAttributes() AppClipAdvancedExperienceImageUpdateRequestDataAttributes {
	if o == nil || IsNil(o.Attributes) {
		var ret AppClipAdvancedExperienceImageUpdateRequestDataAttributes
		return ret
	}
	return *o.Attributes
}

// GetAttributesOk returns a tuple with the Attributes field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AppEncryptionDeclarationDocumentUpdateRequestData) GetAttributesOk() (*AppClipAdvancedExperienceImageUpdateRequestDataAttributes, bool) {
	if o == nil || IsNil(o.Attributes) {
		return nil, false
	}
	return o.Attributes, true
}

// HasAttributes returns a boolean if a field has been set.
func (o *AppEncryptionDeclarationDocumentUpdateRequestData) HasAttributes() bool {
	if o != nil && !IsNil(o.Attributes) {
		return true
	}

	return false
}

// SetAttributes gets a reference to the given AppClipAdvancedExperienceImageUpdateRequestDataAttributes and assigns it to the Attributes field.
func (o *AppEncryptionDeclarationDocumentUpdateRequestData) SetAttributes(v AppClipAdvancedExperienceImageUpdateRequestDataAttributes) {
	o.Attributes = &v
}

func (o AppEncryptionDeclarationDocumentUpdateRequestData) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o AppEncryptionDeclarationDocumentUpdateRequestData) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["type"] = o.Type
	toSerialize["id"] = o.Id
	if !IsNil(o.Attributes) {
		toSerialize["attributes"] = o.Attributes
	}
	return toSerialize, nil
}

type NullableAppEncryptionDeclarationDocumentUpdateRequestData struct {
	value *AppEncryptionDeclarationDocumentUpdateRequestData
	isSet bool
}

func (v NullableAppEncryptionDeclarationDocumentUpdateRequestData) Get() *AppEncryptionDeclarationDocumentUpdateRequestData {
	return v.value
}

func (v *NullableAppEncryptionDeclarationDocumentUpdateRequestData) Set(val *AppEncryptionDeclarationDocumentUpdateRequestData) {
	v.value = val
	v.isSet = true
}

func (v NullableAppEncryptionDeclarationDocumentUpdateRequestData) IsSet() bool {
	return v.isSet
}

func (v *NullableAppEncryptionDeclarationDocumentUpdateRequestData) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableAppEncryptionDeclarationDocumentUpdateRequestData(val *AppEncryptionDeclarationDocumentUpdateRequestData) *NullableAppEncryptionDeclarationDocumentUpdateRequestData {
	return &NullableAppEncryptionDeclarationDocumentUpdateRequestData{value: val, isSet: true}
}

func (v NullableAppEncryptionDeclarationDocumentUpdateRequestData) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableAppEncryptionDeclarationDocumentUpdateRequestData) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
