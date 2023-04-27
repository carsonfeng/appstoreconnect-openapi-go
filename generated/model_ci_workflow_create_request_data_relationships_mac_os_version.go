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

// checks if the CiWorkflowCreateRequestDataRelationshipsMacOsVersion type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &CiWorkflowCreateRequestDataRelationshipsMacOsVersion{}

// CiWorkflowCreateRequestDataRelationshipsMacOsVersion struct for CiWorkflowCreateRequestDataRelationshipsMacOsVersion
type CiWorkflowCreateRequestDataRelationshipsMacOsVersion struct {
	Data CiWorkflowRelationshipsMacOsVersionData `json:"data"`
}

// NewCiWorkflowCreateRequestDataRelationshipsMacOsVersion instantiates a new CiWorkflowCreateRequestDataRelationshipsMacOsVersion object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewCiWorkflowCreateRequestDataRelationshipsMacOsVersion(data CiWorkflowRelationshipsMacOsVersionData) *CiWorkflowCreateRequestDataRelationshipsMacOsVersion {
	this := CiWorkflowCreateRequestDataRelationshipsMacOsVersion{}
	this.Data = data
	return &this
}

// NewCiWorkflowCreateRequestDataRelationshipsMacOsVersionWithDefaults instantiates a new CiWorkflowCreateRequestDataRelationshipsMacOsVersion object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewCiWorkflowCreateRequestDataRelationshipsMacOsVersionWithDefaults() *CiWorkflowCreateRequestDataRelationshipsMacOsVersion {
	this := CiWorkflowCreateRequestDataRelationshipsMacOsVersion{}
	return &this
}

// GetData returns the Data field value
func (o *CiWorkflowCreateRequestDataRelationshipsMacOsVersion) GetData() CiWorkflowRelationshipsMacOsVersionData {
	if o == nil {
		var ret CiWorkflowRelationshipsMacOsVersionData
		return ret
	}

	return o.Data
}

// GetDataOk returns a tuple with the Data field value
// and a boolean to check if the value has been set.
func (o *CiWorkflowCreateRequestDataRelationshipsMacOsVersion) GetDataOk() (*CiWorkflowRelationshipsMacOsVersionData, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Data, true
}

// SetData sets field value
func (o *CiWorkflowCreateRequestDataRelationshipsMacOsVersion) SetData(v CiWorkflowRelationshipsMacOsVersionData) {
	o.Data = v
}

func (o CiWorkflowCreateRequestDataRelationshipsMacOsVersion) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o CiWorkflowCreateRequestDataRelationshipsMacOsVersion) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["data"] = o.Data
	return toSerialize, nil
}

type NullableCiWorkflowCreateRequestDataRelationshipsMacOsVersion struct {
	value *CiWorkflowCreateRequestDataRelationshipsMacOsVersion
	isSet bool
}

func (v NullableCiWorkflowCreateRequestDataRelationshipsMacOsVersion) Get() *CiWorkflowCreateRequestDataRelationshipsMacOsVersion {
	return v.value
}

func (v *NullableCiWorkflowCreateRequestDataRelationshipsMacOsVersion) Set(val *CiWorkflowCreateRequestDataRelationshipsMacOsVersion) {
	v.value = val
	v.isSet = true
}

func (v NullableCiWorkflowCreateRequestDataRelationshipsMacOsVersion) IsSet() bool {
	return v.isSet
}

func (v *NullableCiWorkflowCreateRequestDataRelationshipsMacOsVersion) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableCiWorkflowCreateRequestDataRelationshipsMacOsVersion(val *CiWorkflowCreateRequestDataRelationshipsMacOsVersion) *NullableCiWorkflowCreateRequestDataRelationshipsMacOsVersion {
	return &NullableCiWorkflowCreateRequestDataRelationshipsMacOsVersion{value: val, isSet: true}
}

func (v NullableCiWorkflowCreateRequestDataRelationshipsMacOsVersion) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableCiWorkflowCreateRequestDataRelationshipsMacOsVersion) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
