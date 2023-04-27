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

// checks if the ScmProviderResponse type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &ScmProviderResponse{}

// ScmProviderResponse struct for ScmProviderResponse
type ScmProviderResponse struct {
	Data  ScmProvider   `json:"data"`
	Links DocumentLinks `json:"links"`
}

// NewScmProviderResponse instantiates a new ScmProviderResponse object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewScmProviderResponse(data ScmProvider, links DocumentLinks) *ScmProviderResponse {
	this := ScmProviderResponse{}
	this.Data = data
	this.Links = links
	return &this
}

// NewScmProviderResponseWithDefaults instantiates a new ScmProviderResponse object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewScmProviderResponseWithDefaults() *ScmProviderResponse {
	this := ScmProviderResponse{}
	return &this
}

// GetData returns the Data field value
func (o *ScmProviderResponse) GetData() ScmProvider {
	if o == nil {
		var ret ScmProvider
		return ret
	}

	return o.Data
}

// GetDataOk returns a tuple with the Data field value
// and a boolean to check if the value has been set.
func (o *ScmProviderResponse) GetDataOk() (*ScmProvider, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Data, true
}

// SetData sets field value
func (o *ScmProviderResponse) SetData(v ScmProvider) {
	o.Data = v
}

// GetLinks returns the Links field value
func (o *ScmProviderResponse) GetLinks() DocumentLinks {
	if o == nil {
		var ret DocumentLinks
		return ret
	}

	return o.Links
}

// GetLinksOk returns a tuple with the Links field value
// and a boolean to check if the value has been set.
func (o *ScmProviderResponse) GetLinksOk() (*DocumentLinks, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Links, true
}

// SetLinks sets field value
func (o *ScmProviderResponse) SetLinks(v DocumentLinks) {
	o.Links = v
}

func (o ScmProviderResponse) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o ScmProviderResponse) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["data"] = o.Data
	toSerialize["links"] = o.Links
	return toSerialize, nil
}

type NullableScmProviderResponse struct {
	value *ScmProviderResponse
	isSet bool
}

func (v NullableScmProviderResponse) Get() *ScmProviderResponse {
	return v.value
}

func (v *NullableScmProviderResponse) Set(val *ScmProviderResponse) {
	v.value = val
	v.isSet = true
}

func (v NullableScmProviderResponse) IsSet() bool {
	return v.isSet
}

func (v *NullableScmProviderResponse) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableScmProviderResponse(val *ScmProviderResponse) *NullableScmProviderResponse {
	return &NullableScmProviderResponse{value: val, isSet: true}
}

func (v NullableScmProviderResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableScmProviderResponse) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
