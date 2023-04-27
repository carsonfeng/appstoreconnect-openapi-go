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

// checks if the AppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersionData type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &AppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersionData{}

// AppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersionData struct for AppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersionData
type AppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersionData struct {
	Type string `json:"type"`
	Id   string `json:"id"`
}

// NewAppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersionData instantiates a new AppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersionData object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewAppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersionData(type_ string, id string) *AppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersionData {
	this := AppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersionData{}
	this.Type = type_
	this.Id = id
	return &this
}

// NewAppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersionDataWithDefaults instantiates a new AppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersionData object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersionDataWithDefaults() *AppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersionData {
	this := AppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersionData{}
	return &this
}

// GetType returns the Type field value
func (o *AppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersionData) GetType() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Type
}

// GetTypeOk returns a tuple with the Type field value
// and a boolean to check if the value has been set.
func (o *AppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersionData) GetTypeOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Type, true
}

// SetType sets field value
func (o *AppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersionData) SetType(v string) {
	o.Type = v
}

// GetId returns the Id field value
func (o *AppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersionData) GetId() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Id
}

// GetIdOk returns a tuple with the Id field value
// and a boolean to check if the value has been set.
func (o *AppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersionData) GetIdOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Id, true
}

// SetId sets field value
func (o *AppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersionData) SetId(v string) {
	o.Id = v
}

func (o AppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersionData) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o AppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersionData) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["type"] = o.Type
	toSerialize["id"] = o.Id
	return toSerialize, nil
}

type NullableAppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersionData struct {
	value *AppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersionData
	isSet bool
}

func (v NullableAppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersionData) Get() *AppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersionData {
	return v.value
}

func (v *NullableAppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersionData) Set(val *AppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersionData) {
	v.value = val
	v.isSet = true
}

func (v NullableAppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersionData) IsSet() bool {
	return v.isSet
}

func (v *NullableAppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersionData) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableAppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersionData(val *AppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersionData) *NullableAppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersionData {
	return &NullableAppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersionData{value: val, isSet: true}
}

func (v NullableAppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersionData) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableAppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersionData) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
