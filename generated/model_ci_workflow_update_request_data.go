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

// checks if the CiWorkflowUpdateRequestData type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &CiWorkflowUpdateRequestData{}

// CiWorkflowUpdateRequestData struct for CiWorkflowUpdateRequestData
type CiWorkflowUpdateRequestData struct {
	Type          string                                    `json:"type"`
	Id            string                                    `json:"id"`
	Attributes    *CiWorkflowUpdateRequestDataAttributes    `json:"attributes,omitempty"`
	Relationships *CiWorkflowUpdateRequestDataRelationships `json:"relationships,omitempty"`
}

// NewCiWorkflowUpdateRequestData instantiates a new CiWorkflowUpdateRequestData object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewCiWorkflowUpdateRequestData(type_ string, id string) *CiWorkflowUpdateRequestData {
	this := CiWorkflowUpdateRequestData{}
	this.Type = type_
	this.Id = id
	return &this
}

// NewCiWorkflowUpdateRequestDataWithDefaults instantiates a new CiWorkflowUpdateRequestData object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewCiWorkflowUpdateRequestDataWithDefaults() *CiWorkflowUpdateRequestData {
	this := CiWorkflowUpdateRequestData{}
	return &this
}

// GetType returns the Type field value
func (o *CiWorkflowUpdateRequestData) GetType() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Type
}

// GetTypeOk returns a tuple with the Type field value
// and a boolean to check if the value has been set.
func (o *CiWorkflowUpdateRequestData) GetTypeOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Type, true
}

// SetType sets field value
func (o *CiWorkflowUpdateRequestData) SetType(v string) {
	o.Type = v
}

// GetId returns the Id field value
func (o *CiWorkflowUpdateRequestData) GetId() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Id
}

// GetIdOk returns a tuple with the Id field value
// and a boolean to check if the value has been set.
func (o *CiWorkflowUpdateRequestData) GetIdOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Id, true
}

// SetId sets field value
func (o *CiWorkflowUpdateRequestData) SetId(v string) {
	o.Id = v
}

// GetAttributes returns the Attributes field value if set, zero value otherwise.
func (o *CiWorkflowUpdateRequestData) GetAttributes() CiWorkflowUpdateRequestDataAttributes {
	if o == nil || IsNil(o.Attributes) {
		var ret CiWorkflowUpdateRequestDataAttributes
		return ret
	}
	return *o.Attributes
}

// GetAttributesOk returns a tuple with the Attributes field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CiWorkflowUpdateRequestData) GetAttributesOk() (*CiWorkflowUpdateRequestDataAttributes, bool) {
	if o == nil || IsNil(o.Attributes) {
		return nil, false
	}
	return o.Attributes, true
}

// HasAttributes returns a boolean if a field has been set.
func (o *CiWorkflowUpdateRequestData) HasAttributes() bool {
	if o != nil && !IsNil(o.Attributes) {
		return true
	}

	return false
}

// SetAttributes gets a reference to the given CiWorkflowUpdateRequestDataAttributes and assigns it to the Attributes field.
func (o *CiWorkflowUpdateRequestData) SetAttributes(v CiWorkflowUpdateRequestDataAttributes) {
	o.Attributes = &v
}

// GetRelationships returns the Relationships field value if set, zero value otherwise.
func (o *CiWorkflowUpdateRequestData) GetRelationships() CiWorkflowUpdateRequestDataRelationships {
	if o == nil || IsNil(o.Relationships) {
		var ret CiWorkflowUpdateRequestDataRelationships
		return ret
	}
	return *o.Relationships
}

// GetRelationshipsOk returns a tuple with the Relationships field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CiWorkflowUpdateRequestData) GetRelationshipsOk() (*CiWorkflowUpdateRequestDataRelationships, bool) {
	if o == nil || IsNil(o.Relationships) {
		return nil, false
	}
	return o.Relationships, true
}

// HasRelationships returns a boolean if a field has been set.
func (o *CiWorkflowUpdateRequestData) HasRelationships() bool {
	if o != nil && !IsNil(o.Relationships) {
		return true
	}

	return false
}

// SetRelationships gets a reference to the given CiWorkflowUpdateRequestDataRelationships and assigns it to the Relationships field.
func (o *CiWorkflowUpdateRequestData) SetRelationships(v CiWorkflowUpdateRequestDataRelationships) {
	o.Relationships = &v
}

func (o CiWorkflowUpdateRequestData) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o CiWorkflowUpdateRequestData) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["type"] = o.Type
	toSerialize["id"] = o.Id
	if !IsNil(o.Attributes) {
		toSerialize["attributes"] = o.Attributes
	}
	if !IsNil(o.Relationships) {
		toSerialize["relationships"] = o.Relationships
	}
	return toSerialize, nil
}

type NullableCiWorkflowUpdateRequestData struct {
	value *CiWorkflowUpdateRequestData
	isSet bool
}

func (v NullableCiWorkflowUpdateRequestData) Get() *CiWorkflowUpdateRequestData {
	return v.value
}

func (v *NullableCiWorkflowUpdateRequestData) Set(val *CiWorkflowUpdateRequestData) {
	v.value = val
	v.isSet = true
}

func (v NullableCiWorkflowUpdateRequestData) IsSet() bool {
	return v.isSet
}

func (v *NullableCiWorkflowUpdateRequestData) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableCiWorkflowUpdateRequestData(val *CiWorkflowUpdateRequestData) *NullableCiWorkflowUpdateRequestData {
	return &NullableCiWorkflowUpdateRequestData{value: val, isSet: true}
}

func (v NullableCiWorkflowUpdateRequestData) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableCiWorkflowUpdateRequestData) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
