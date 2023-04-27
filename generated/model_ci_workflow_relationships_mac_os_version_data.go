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

// checks if the CiWorkflowRelationshipsMacOsVersionData type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &CiWorkflowRelationshipsMacOsVersionData{}

// CiWorkflowRelationshipsMacOsVersionData struct for CiWorkflowRelationshipsMacOsVersionData
type CiWorkflowRelationshipsMacOsVersionData struct {
	Type string `json:"type"`
	Id   string `json:"id"`
}

// NewCiWorkflowRelationshipsMacOsVersionData instantiates a new CiWorkflowRelationshipsMacOsVersionData object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewCiWorkflowRelationshipsMacOsVersionData(type_ string, id string) *CiWorkflowRelationshipsMacOsVersionData {
	this := CiWorkflowRelationshipsMacOsVersionData{}
	this.Type = type_
	this.Id = id
	return &this
}

// NewCiWorkflowRelationshipsMacOsVersionDataWithDefaults instantiates a new CiWorkflowRelationshipsMacOsVersionData object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewCiWorkflowRelationshipsMacOsVersionDataWithDefaults() *CiWorkflowRelationshipsMacOsVersionData {
	this := CiWorkflowRelationshipsMacOsVersionData{}
	return &this
}

// GetType returns the Type field value
func (o *CiWorkflowRelationshipsMacOsVersionData) GetType() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Type
}

// GetTypeOk returns a tuple with the Type field value
// and a boolean to check if the value has been set.
func (o *CiWorkflowRelationshipsMacOsVersionData) GetTypeOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Type, true
}

// SetType sets field value
func (o *CiWorkflowRelationshipsMacOsVersionData) SetType(v string) {
	o.Type = v
}

// GetId returns the Id field value
func (o *CiWorkflowRelationshipsMacOsVersionData) GetId() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Id
}

// GetIdOk returns a tuple with the Id field value
// and a boolean to check if the value has been set.
func (o *CiWorkflowRelationshipsMacOsVersionData) GetIdOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Id, true
}

// SetId sets field value
func (o *CiWorkflowRelationshipsMacOsVersionData) SetId(v string) {
	o.Id = v
}

func (o CiWorkflowRelationshipsMacOsVersionData) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o CiWorkflowRelationshipsMacOsVersionData) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["type"] = o.Type
	toSerialize["id"] = o.Id
	return toSerialize, nil
}

type NullableCiWorkflowRelationshipsMacOsVersionData struct {
	value *CiWorkflowRelationshipsMacOsVersionData
	isSet bool
}

func (v NullableCiWorkflowRelationshipsMacOsVersionData) Get() *CiWorkflowRelationshipsMacOsVersionData {
	return v.value
}

func (v *NullableCiWorkflowRelationshipsMacOsVersionData) Set(val *CiWorkflowRelationshipsMacOsVersionData) {
	v.value = val
	v.isSet = true
}

func (v NullableCiWorkflowRelationshipsMacOsVersionData) IsSet() bool {
	return v.isSet
}

func (v *NullableCiWorkflowRelationshipsMacOsVersionData) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableCiWorkflowRelationshipsMacOsVersionData(val *CiWorkflowRelationshipsMacOsVersionData) *NullableCiWorkflowRelationshipsMacOsVersionData {
	return &NullableCiWorkflowRelationshipsMacOsVersionData{value: val, isSet: true}
}

func (v NullableCiWorkflowRelationshipsMacOsVersionData) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableCiWorkflowRelationshipsMacOsVersionData) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
