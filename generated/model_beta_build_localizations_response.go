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

// checks if the BetaBuildLocalizationsResponse type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &BetaBuildLocalizationsResponse{}

// BetaBuildLocalizationsResponse struct for BetaBuildLocalizationsResponse
type BetaBuildLocalizationsResponse struct {
	Data     []BetaBuildLocalization `json:"data"`
	Included []Build                 `json:"included,omitempty"`
	Links    PagedDocumentLinks      `json:"links"`
	Meta     *PagingInformation      `json:"meta,omitempty"`
}

// NewBetaBuildLocalizationsResponse instantiates a new BetaBuildLocalizationsResponse object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewBetaBuildLocalizationsResponse(data []BetaBuildLocalization, links PagedDocumentLinks) *BetaBuildLocalizationsResponse {
	this := BetaBuildLocalizationsResponse{}
	this.Data = data
	this.Links = links
	return &this
}

// NewBetaBuildLocalizationsResponseWithDefaults instantiates a new BetaBuildLocalizationsResponse object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewBetaBuildLocalizationsResponseWithDefaults() *BetaBuildLocalizationsResponse {
	this := BetaBuildLocalizationsResponse{}
	return &this
}

// GetData returns the Data field value
func (o *BetaBuildLocalizationsResponse) GetData() []BetaBuildLocalization {
	if o == nil {
		var ret []BetaBuildLocalization
		return ret
	}

	return o.Data
}

// GetDataOk returns a tuple with the Data field value
// and a boolean to check if the value has been set.
func (o *BetaBuildLocalizationsResponse) GetDataOk() ([]BetaBuildLocalization, bool) {
	if o == nil {
		return nil, false
	}
	return o.Data, true
}

// SetData sets field value
func (o *BetaBuildLocalizationsResponse) SetData(v []BetaBuildLocalization) {
	o.Data = v
}

// GetIncluded returns the Included field value if set, zero value otherwise.
func (o *BetaBuildLocalizationsResponse) GetIncluded() []Build {
	if o == nil || IsNil(o.Included) {
		var ret []Build
		return ret
	}
	return o.Included
}

// GetIncludedOk returns a tuple with the Included field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *BetaBuildLocalizationsResponse) GetIncludedOk() ([]Build, bool) {
	if o == nil || IsNil(o.Included) {
		return nil, false
	}
	return o.Included, true
}

// HasIncluded returns a boolean if a field has been set.
func (o *BetaBuildLocalizationsResponse) HasIncluded() bool {
	if o != nil && !IsNil(o.Included) {
		return true
	}

	return false
}

// SetIncluded gets a reference to the given []Build and assigns it to the Included field.
func (o *BetaBuildLocalizationsResponse) SetIncluded(v []Build) {
	o.Included = v
}

// GetLinks returns the Links field value
func (o *BetaBuildLocalizationsResponse) GetLinks() PagedDocumentLinks {
	if o == nil {
		var ret PagedDocumentLinks
		return ret
	}

	return o.Links
}

// GetLinksOk returns a tuple with the Links field value
// and a boolean to check if the value has been set.
func (o *BetaBuildLocalizationsResponse) GetLinksOk() (*PagedDocumentLinks, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Links, true
}

// SetLinks sets field value
func (o *BetaBuildLocalizationsResponse) SetLinks(v PagedDocumentLinks) {
	o.Links = v
}

// GetMeta returns the Meta field value if set, zero value otherwise.
func (o *BetaBuildLocalizationsResponse) GetMeta() PagingInformation {
	if o == nil || IsNil(o.Meta) {
		var ret PagingInformation
		return ret
	}
	return *o.Meta
}

// GetMetaOk returns a tuple with the Meta field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *BetaBuildLocalizationsResponse) GetMetaOk() (*PagingInformation, bool) {
	if o == nil || IsNil(o.Meta) {
		return nil, false
	}
	return o.Meta, true
}

// HasMeta returns a boolean if a field has been set.
func (o *BetaBuildLocalizationsResponse) HasMeta() bool {
	if o != nil && !IsNil(o.Meta) {
		return true
	}

	return false
}

// SetMeta gets a reference to the given PagingInformation and assigns it to the Meta field.
func (o *BetaBuildLocalizationsResponse) SetMeta(v PagingInformation) {
	o.Meta = &v
}

func (o BetaBuildLocalizationsResponse) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o BetaBuildLocalizationsResponse) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["data"] = o.Data
	if !IsNil(o.Included) {
		toSerialize["included"] = o.Included
	}
	toSerialize["links"] = o.Links
	if !IsNil(o.Meta) {
		toSerialize["meta"] = o.Meta
	}
	return toSerialize, nil
}

type NullableBetaBuildLocalizationsResponse struct {
	value *BetaBuildLocalizationsResponse
	isSet bool
}

func (v NullableBetaBuildLocalizationsResponse) Get() *BetaBuildLocalizationsResponse {
	return v.value
}

func (v *NullableBetaBuildLocalizationsResponse) Set(val *BetaBuildLocalizationsResponse) {
	v.value = val
	v.isSet = true
}

func (v NullableBetaBuildLocalizationsResponse) IsSet() bool {
	return v.isSet
}

func (v *NullableBetaBuildLocalizationsResponse) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableBetaBuildLocalizationsResponse(val *BetaBuildLocalizationsResponse) *NullableBetaBuildLocalizationsResponse {
	return &NullableBetaBuildLocalizationsResponse{value: val, isSet: true}
}

func (v NullableBetaBuildLocalizationsResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableBetaBuildLocalizationsResponse) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
