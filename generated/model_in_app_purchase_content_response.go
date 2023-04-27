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

// checks if the InAppPurchaseContentResponse type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &InAppPurchaseContentResponse{}

// InAppPurchaseContentResponse struct for InAppPurchaseContentResponse
type InAppPurchaseContentResponse struct {
	Data     InAppPurchaseContent `json:"data"`
	Included []InAppPurchaseV2    `json:"included,omitempty"`
	Links    DocumentLinks        `json:"links"`
}

// NewInAppPurchaseContentResponse instantiates a new InAppPurchaseContentResponse object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewInAppPurchaseContentResponse(data InAppPurchaseContent, links DocumentLinks) *InAppPurchaseContentResponse {
	this := InAppPurchaseContentResponse{}
	this.Data = data
	this.Links = links
	return &this
}

// NewInAppPurchaseContentResponseWithDefaults instantiates a new InAppPurchaseContentResponse object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewInAppPurchaseContentResponseWithDefaults() *InAppPurchaseContentResponse {
	this := InAppPurchaseContentResponse{}
	return &this
}

// GetData returns the Data field value
func (o *InAppPurchaseContentResponse) GetData() InAppPurchaseContent {
	if o == nil {
		var ret InAppPurchaseContent
		return ret
	}

	return o.Data
}

// GetDataOk returns a tuple with the Data field value
// and a boolean to check if the value has been set.
func (o *InAppPurchaseContentResponse) GetDataOk() (*InAppPurchaseContent, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Data, true
}

// SetData sets field value
func (o *InAppPurchaseContentResponse) SetData(v InAppPurchaseContent) {
	o.Data = v
}

// GetIncluded returns the Included field value if set, zero value otherwise.
func (o *InAppPurchaseContentResponse) GetIncluded() []InAppPurchaseV2 {
	if o == nil || IsNil(o.Included) {
		var ret []InAppPurchaseV2
		return ret
	}
	return o.Included
}

// GetIncludedOk returns a tuple with the Included field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *InAppPurchaseContentResponse) GetIncludedOk() ([]InAppPurchaseV2, bool) {
	if o == nil || IsNil(o.Included) {
		return nil, false
	}
	return o.Included, true
}

// HasIncluded returns a boolean if a field has been set.
func (o *InAppPurchaseContentResponse) HasIncluded() bool {
	if o != nil && !IsNil(o.Included) {
		return true
	}

	return false
}

// SetIncluded gets a reference to the given []InAppPurchaseV2 and assigns it to the Included field.
func (o *InAppPurchaseContentResponse) SetIncluded(v []InAppPurchaseV2) {
	o.Included = v
}

// GetLinks returns the Links field value
func (o *InAppPurchaseContentResponse) GetLinks() DocumentLinks {
	if o == nil {
		var ret DocumentLinks
		return ret
	}

	return o.Links
}

// GetLinksOk returns a tuple with the Links field value
// and a boolean to check if the value has been set.
func (o *InAppPurchaseContentResponse) GetLinksOk() (*DocumentLinks, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Links, true
}

// SetLinks sets field value
func (o *InAppPurchaseContentResponse) SetLinks(v DocumentLinks) {
	o.Links = v
}

func (o InAppPurchaseContentResponse) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o InAppPurchaseContentResponse) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["data"] = o.Data
	if !IsNil(o.Included) {
		toSerialize["included"] = o.Included
	}
	toSerialize["links"] = o.Links
	return toSerialize, nil
}

type NullableInAppPurchaseContentResponse struct {
	value *InAppPurchaseContentResponse
	isSet bool
}

func (v NullableInAppPurchaseContentResponse) Get() *InAppPurchaseContentResponse {
	return v.value
}

func (v *NullableInAppPurchaseContentResponse) Set(val *InAppPurchaseContentResponse) {
	v.value = val
	v.isSet = true
}

func (v NullableInAppPurchaseContentResponse) IsSet() bool {
	return v.isSet
}

func (v *NullableInAppPurchaseContentResponse) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableInAppPurchaseContentResponse(val *InAppPurchaseContentResponse) *NullableInAppPurchaseContentResponse {
	return &NullableInAppPurchaseContentResponse{value: val, isSet: true}
}

func (v NullableInAppPurchaseContentResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableInAppPurchaseContentResponse) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
