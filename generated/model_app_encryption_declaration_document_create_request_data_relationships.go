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

// checks if the AppEncryptionDeclarationDocumentCreateRequestDataRelationships type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &AppEncryptionDeclarationDocumentCreateRequestDataRelationships{}

// AppEncryptionDeclarationDocumentCreateRequestDataRelationships struct for AppEncryptionDeclarationDocumentCreateRequestDataRelationships
type AppEncryptionDeclarationDocumentCreateRequestDataRelationships struct {
	AppEncryptionDeclaration AppEncryptionDeclarationDocumentCreateRequestDataRelationshipsAppEncryptionDeclaration `json:"appEncryptionDeclaration"`
}

// NewAppEncryptionDeclarationDocumentCreateRequestDataRelationships instantiates a new AppEncryptionDeclarationDocumentCreateRequestDataRelationships object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewAppEncryptionDeclarationDocumentCreateRequestDataRelationships(appEncryptionDeclaration AppEncryptionDeclarationDocumentCreateRequestDataRelationshipsAppEncryptionDeclaration) *AppEncryptionDeclarationDocumentCreateRequestDataRelationships {
	this := AppEncryptionDeclarationDocumentCreateRequestDataRelationships{}
	this.AppEncryptionDeclaration = appEncryptionDeclaration
	return &this
}

// NewAppEncryptionDeclarationDocumentCreateRequestDataRelationshipsWithDefaults instantiates a new AppEncryptionDeclarationDocumentCreateRequestDataRelationships object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAppEncryptionDeclarationDocumentCreateRequestDataRelationshipsWithDefaults() *AppEncryptionDeclarationDocumentCreateRequestDataRelationships {
	this := AppEncryptionDeclarationDocumentCreateRequestDataRelationships{}
	return &this
}

// GetAppEncryptionDeclaration returns the AppEncryptionDeclaration field value
func (o *AppEncryptionDeclarationDocumentCreateRequestDataRelationships) GetAppEncryptionDeclaration() AppEncryptionDeclarationDocumentCreateRequestDataRelationshipsAppEncryptionDeclaration {
	if o == nil {
		var ret AppEncryptionDeclarationDocumentCreateRequestDataRelationshipsAppEncryptionDeclaration
		return ret
	}

	return o.AppEncryptionDeclaration
}

// GetAppEncryptionDeclarationOk returns a tuple with the AppEncryptionDeclaration field value
// and a boolean to check if the value has been set.
func (o *AppEncryptionDeclarationDocumentCreateRequestDataRelationships) GetAppEncryptionDeclarationOk() (*AppEncryptionDeclarationDocumentCreateRequestDataRelationshipsAppEncryptionDeclaration, bool) {
	if o == nil {
		return nil, false
	}
	return &o.AppEncryptionDeclaration, true
}

// SetAppEncryptionDeclaration sets field value
func (o *AppEncryptionDeclarationDocumentCreateRequestDataRelationships) SetAppEncryptionDeclaration(v AppEncryptionDeclarationDocumentCreateRequestDataRelationshipsAppEncryptionDeclaration) {
	o.AppEncryptionDeclaration = v
}

func (o AppEncryptionDeclarationDocumentCreateRequestDataRelationships) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o AppEncryptionDeclarationDocumentCreateRequestDataRelationships) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["appEncryptionDeclaration"] = o.AppEncryptionDeclaration
	return toSerialize, nil
}

type NullableAppEncryptionDeclarationDocumentCreateRequestDataRelationships struct {
	value *AppEncryptionDeclarationDocumentCreateRequestDataRelationships
	isSet bool
}

func (v NullableAppEncryptionDeclarationDocumentCreateRequestDataRelationships) Get() *AppEncryptionDeclarationDocumentCreateRequestDataRelationships {
	return v.value
}

func (v *NullableAppEncryptionDeclarationDocumentCreateRequestDataRelationships) Set(val *AppEncryptionDeclarationDocumentCreateRequestDataRelationships) {
	v.value = val
	v.isSet = true
}

func (v NullableAppEncryptionDeclarationDocumentCreateRequestDataRelationships) IsSet() bool {
	return v.isSet
}

func (v *NullableAppEncryptionDeclarationDocumentCreateRequestDataRelationships) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableAppEncryptionDeclarationDocumentCreateRequestDataRelationships(val *AppEncryptionDeclarationDocumentCreateRequestDataRelationships) *NullableAppEncryptionDeclarationDocumentCreateRequestDataRelationships {
	return &NullableAppEncryptionDeclarationDocumentCreateRequestDataRelationships{value: val, isSet: true}
}

func (v NullableAppEncryptionDeclarationDocumentCreateRequestDataRelationships) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableAppEncryptionDeclarationDocumentCreateRequestDataRelationships) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
