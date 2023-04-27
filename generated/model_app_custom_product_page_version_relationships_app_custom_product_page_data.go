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

// checks if the AppCustomProductPageVersionRelationshipsAppCustomProductPageData type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &AppCustomProductPageVersionRelationshipsAppCustomProductPageData{}

// AppCustomProductPageVersionRelationshipsAppCustomProductPageData struct for AppCustomProductPageVersionRelationshipsAppCustomProductPageData
type AppCustomProductPageVersionRelationshipsAppCustomProductPageData struct {
	Type string `json:"type"`
	Id   string `json:"id"`
}

// NewAppCustomProductPageVersionRelationshipsAppCustomProductPageData instantiates a new AppCustomProductPageVersionRelationshipsAppCustomProductPageData object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewAppCustomProductPageVersionRelationshipsAppCustomProductPageData(type_ string, id string) *AppCustomProductPageVersionRelationshipsAppCustomProductPageData {
	this := AppCustomProductPageVersionRelationshipsAppCustomProductPageData{}
	this.Type = type_
	this.Id = id
	return &this
}

// NewAppCustomProductPageVersionRelationshipsAppCustomProductPageDataWithDefaults instantiates a new AppCustomProductPageVersionRelationshipsAppCustomProductPageData object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAppCustomProductPageVersionRelationshipsAppCustomProductPageDataWithDefaults() *AppCustomProductPageVersionRelationshipsAppCustomProductPageData {
	this := AppCustomProductPageVersionRelationshipsAppCustomProductPageData{}
	return &this
}

// GetType returns the Type field value
func (o *AppCustomProductPageVersionRelationshipsAppCustomProductPageData) GetType() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Type
}

// GetTypeOk returns a tuple with the Type field value
// and a boolean to check if the value has been set.
func (o *AppCustomProductPageVersionRelationshipsAppCustomProductPageData) GetTypeOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Type, true
}

// SetType sets field value
func (o *AppCustomProductPageVersionRelationshipsAppCustomProductPageData) SetType(v string) {
	o.Type = v
}

// GetId returns the Id field value
func (o *AppCustomProductPageVersionRelationshipsAppCustomProductPageData) GetId() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Id
}

// GetIdOk returns a tuple with the Id field value
// and a boolean to check if the value has been set.
func (o *AppCustomProductPageVersionRelationshipsAppCustomProductPageData) GetIdOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Id, true
}

// SetId sets field value
func (o *AppCustomProductPageVersionRelationshipsAppCustomProductPageData) SetId(v string) {
	o.Id = v
}

func (o AppCustomProductPageVersionRelationshipsAppCustomProductPageData) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o AppCustomProductPageVersionRelationshipsAppCustomProductPageData) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["type"] = o.Type
	toSerialize["id"] = o.Id
	return toSerialize, nil
}

type NullableAppCustomProductPageVersionRelationshipsAppCustomProductPageData struct {
	value *AppCustomProductPageVersionRelationshipsAppCustomProductPageData
	isSet bool
}

func (v NullableAppCustomProductPageVersionRelationshipsAppCustomProductPageData) Get() *AppCustomProductPageVersionRelationshipsAppCustomProductPageData {
	return v.value
}

func (v *NullableAppCustomProductPageVersionRelationshipsAppCustomProductPageData) Set(val *AppCustomProductPageVersionRelationshipsAppCustomProductPageData) {
	v.value = val
	v.isSet = true
}

func (v NullableAppCustomProductPageVersionRelationshipsAppCustomProductPageData) IsSet() bool {
	return v.isSet
}

func (v *NullableAppCustomProductPageVersionRelationshipsAppCustomProductPageData) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableAppCustomProductPageVersionRelationshipsAppCustomProductPageData(val *AppCustomProductPageVersionRelationshipsAppCustomProductPageData) *NullableAppCustomProductPageVersionRelationshipsAppCustomProductPageData {
	return &NullableAppCustomProductPageVersionRelationshipsAppCustomProductPageData{value: val, isSet: true}
}

func (v NullableAppCustomProductPageVersionRelationshipsAppCustomProductPageData) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableAppCustomProductPageVersionRelationshipsAppCustomProductPageData) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
