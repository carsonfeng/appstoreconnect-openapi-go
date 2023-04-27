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

// checks if the AppClipDefaultExperienceReleaseWithAppStoreVersionLinkageRequest type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &AppClipDefaultExperienceReleaseWithAppStoreVersionLinkageRequest{}

// AppClipDefaultExperienceReleaseWithAppStoreVersionLinkageRequest struct for AppClipDefaultExperienceReleaseWithAppStoreVersionLinkageRequest
type AppClipDefaultExperienceReleaseWithAppStoreVersionLinkageRequest struct {
	Data AppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersionData `json:"data"`
}

// NewAppClipDefaultExperienceReleaseWithAppStoreVersionLinkageRequest instantiates a new AppClipDefaultExperienceReleaseWithAppStoreVersionLinkageRequest object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewAppClipDefaultExperienceReleaseWithAppStoreVersionLinkageRequest(data AppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersionData) *AppClipDefaultExperienceReleaseWithAppStoreVersionLinkageRequest {
	this := AppClipDefaultExperienceReleaseWithAppStoreVersionLinkageRequest{}
	this.Data = data
	return &this
}

// NewAppClipDefaultExperienceReleaseWithAppStoreVersionLinkageRequestWithDefaults instantiates a new AppClipDefaultExperienceReleaseWithAppStoreVersionLinkageRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAppClipDefaultExperienceReleaseWithAppStoreVersionLinkageRequestWithDefaults() *AppClipDefaultExperienceReleaseWithAppStoreVersionLinkageRequest {
	this := AppClipDefaultExperienceReleaseWithAppStoreVersionLinkageRequest{}
	return &this
}

// GetData returns the Data field value
func (o *AppClipDefaultExperienceReleaseWithAppStoreVersionLinkageRequest) GetData() AppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersionData {
	if o == nil {
		var ret AppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersionData
		return ret
	}

	return o.Data
}

// GetDataOk returns a tuple with the Data field value
// and a boolean to check if the value has been set.
func (o *AppClipDefaultExperienceReleaseWithAppStoreVersionLinkageRequest) GetDataOk() (*AppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersionData, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Data, true
}

// SetData sets field value
func (o *AppClipDefaultExperienceReleaseWithAppStoreVersionLinkageRequest) SetData(v AppClipDefaultExperienceRelationshipsReleaseWithAppStoreVersionData) {
	o.Data = v
}

func (o AppClipDefaultExperienceReleaseWithAppStoreVersionLinkageRequest) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o AppClipDefaultExperienceReleaseWithAppStoreVersionLinkageRequest) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["data"] = o.Data
	return toSerialize, nil
}

type NullableAppClipDefaultExperienceReleaseWithAppStoreVersionLinkageRequest struct {
	value *AppClipDefaultExperienceReleaseWithAppStoreVersionLinkageRequest
	isSet bool
}

func (v NullableAppClipDefaultExperienceReleaseWithAppStoreVersionLinkageRequest) Get() *AppClipDefaultExperienceReleaseWithAppStoreVersionLinkageRequest {
	return v.value
}

func (v *NullableAppClipDefaultExperienceReleaseWithAppStoreVersionLinkageRequest) Set(val *AppClipDefaultExperienceReleaseWithAppStoreVersionLinkageRequest) {
	v.value = val
	v.isSet = true
}

func (v NullableAppClipDefaultExperienceReleaseWithAppStoreVersionLinkageRequest) IsSet() bool {
	return v.isSet
}

func (v *NullableAppClipDefaultExperienceReleaseWithAppStoreVersionLinkageRequest) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableAppClipDefaultExperienceReleaseWithAppStoreVersionLinkageRequest(val *AppClipDefaultExperienceReleaseWithAppStoreVersionLinkageRequest) *NullableAppClipDefaultExperienceReleaseWithAppStoreVersionLinkageRequest {
	return &NullableAppClipDefaultExperienceReleaseWithAppStoreVersionLinkageRequest{value: val, isSet: true}
}

func (v NullableAppClipDefaultExperienceReleaseWithAppStoreVersionLinkageRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableAppClipDefaultExperienceReleaseWithAppStoreVersionLinkageRequest) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
