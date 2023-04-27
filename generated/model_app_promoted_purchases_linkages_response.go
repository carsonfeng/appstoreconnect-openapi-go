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

// checks if the AppPromotedPurchasesLinkagesResponse type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &AppPromotedPurchasesLinkagesResponse{}

// AppPromotedPurchasesLinkagesResponse struct for AppPromotedPurchasesLinkagesResponse
type AppPromotedPurchasesLinkagesResponse struct {
	Data  []AppRelationshipsPromotedPurchasesDataInner `json:"data"`
	Links PagedDocumentLinks                           `json:"links"`
	Meta  *PagingInformation                           `json:"meta,omitempty"`
}

// NewAppPromotedPurchasesLinkagesResponse instantiates a new AppPromotedPurchasesLinkagesResponse object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewAppPromotedPurchasesLinkagesResponse(data []AppRelationshipsPromotedPurchasesDataInner, links PagedDocumentLinks) *AppPromotedPurchasesLinkagesResponse {
	this := AppPromotedPurchasesLinkagesResponse{}
	this.Data = data
	this.Links = links
	return &this
}

// NewAppPromotedPurchasesLinkagesResponseWithDefaults instantiates a new AppPromotedPurchasesLinkagesResponse object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAppPromotedPurchasesLinkagesResponseWithDefaults() *AppPromotedPurchasesLinkagesResponse {
	this := AppPromotedPurchasesLinkagesResponse{}
	return &this
}

// GetData returns the Data field value
func (o *AppPromotedPurchasesLinkagesResponse) GetData() []AppRelationshipsPromotedPurchasesDataInner {
	if o == nil {
		var ret []AppRelationshipsPromotedPurchasesDataInner
		return ret
	}

	return o.Data
}

// GetDataOk returns a tuple with the Data field value
// and a boolean to check if the value has been set.
func (o *AppPromotedPurchasesLinkagesResponse) GetDataOk() ([]AppRelationshipsPromotedPurchasesDataInner, bool) {
	if o == nil {
		return nil, false
	}
	return o.Data, true
}

// SetData sets field value
func (o *AppPromotedPurchasesLinkagesResponse) SetData(v []AppRelationshipsPromotedPurchasesDataInner) {
	o.Data = v
}

// GetLinks returns the Links field value
func (o *AppPromotedPurchasesLinkagesResponse) GetLinks() PagedDocumentLinks {
	if o == nil {
		var ret PagedDocumentLinks
		return ret
	}

	return o.Links
}

// GetLinksOk returns a tuple with the Links field value
// and a boolean to check if the value has been set.
func (o *AppPromotedPurchasesLinkagesResponse) GetLinksOk() (*PagedDocumentLinks, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Links, true
}

// SetLinks sets field value
func (o *AppPromotedPurchasesLinkagesResponse) SetLinks(v PagedDocumentLinks) {
	o.Links = v
}

// GetMeta returns the Meta field value if set, zero value otherwise.
func (o *AppPromotedPurchasesLinkagesResponse) GetMeta() PagingInformation {
	if o == nil || IsNil(o.Meta) {
		var ret PagingInformation
		return ret
	}
	return *o.Meta
}

// GetMetaOk returns a tuple with the Meta field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AppPromotedPurchasesLinkagesResponse) GetMetaOk() (*PagingInformation, bool) {
	if o == nil || IsNil(o.Meta) {
		return nil, false
	}
	return o.Meta, true
}

// HasMeta returns a boolean if a field has been set.
func (o *AppPromotedPurchasesLinkagesResponse) HasMeta() bool {
	if o != nil && !IsNil(o.Meta) {
		return true
	}

	return false
}

// SetMeta gets a reference to the given PagingInformation and assigns it to the Meta field.
func (o *AppPromotedPurchasesLinkagesResponse) SetMeta(v PagingInformation) {
	o.Meta = &v
}

func (o AppPromotedPurchasesLinkagesResponse) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o AppPromotedPurchasesLinkagesResponse) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["data"] = o.Data
	toSerialize["links"] = o.Links
	if !IsNil(o.Meta) {
		toSerialize["meta"] = o.Meta
	}
	return toSerialize, nil
}

type NullableAppPromotedPurchasesLinkagesResponse struct {
	value *AppPromotedPurchasesLinkagesResponse
	isSet bool
}

func (v NullableAppPromotedPurchasesLinkagesResponse) Get() *AppPromotedPurchasesLinkagesResponse {
	return v.value
}

func (v *NullableAppPromotedPurchasesLinkagesResponse) Set(val *AppPromotedPurchasesLinkagesResponse) {
	v.value = val
	v.isSet = true
}

func (v NullableAppPromotedPurchasesLinkagesResponse) IsSet() bool {
	return v.isSet
}

func (v *NullableAppPromotedPurchasesLinkagesResponse) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableAppPromotedPurchasesLinkagesResponse(val *AppPromotedPurchasesLinkagesResponse) *NullableAppPromotedPurchasesLinkagesResponse {
	return &NullableAppPromotedPurchasesLinkagesResponse{value: val, isSet: true}
}

func (v NullableAppPromotedPurchasesLinkagesResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableAppPromotedPurchasesLinkagesResponse) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
