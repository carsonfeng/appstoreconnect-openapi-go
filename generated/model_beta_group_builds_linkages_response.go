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

// checks if the BetaGroupBuildsLinkagesResponse type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &BetaGroupBuildsLinkagesResponse{}

// BetaGroupBuildsLinkagesResponse struct for BetaGroupBuildsLinkagesResponse
type BetaGroupBuildsLinkagesResponse struct {
	Data  []AppEncryptionDeclarationRelationshipsBuildsDataInner `json:"data"`
	Links PagedDocumentLinks                                     `json:"links"`
	Meta  *PagingInformation                                     `json:"meta,omitempty"`
}

// NewBetaGroupBuildsLinkagesResponse instantiates a new BetaGroupBuildsLinkagesResponse object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewBetaGroupBuildsLinkagesResponse(data []AppEncryptionDeclarationRelationshipsBuildsDataInner, links PagedDocumentLinks) *BetaGroupBuildsLinkagesResponse {
	this := BetaGroupBuildsLinkagesResponse{}
	this.Data = data
	this.Links = links
	return &this
}

// NewBetaGroupBuildsLinkagesResponseWithDefaults instantiates a new BetaGroupBuildsLinkagesResponse object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewBetaGroupBuildsLinkagesResponseWithDefaults() *BetaGroupBuildsLinkagesResponse {
	this := BetaGroupBuildsLinkagesResponse{}
	return &this
}

// GetData returns the Data field value
func (o *BetaGroupBuildsLinkagesResponse) GetData() []AppEncryptionDeclarationRelationshipsBuildsDataInner {
	if o == nil {
		var ret []AppEncryptionDeclarationRelationshipsBuildsDataInner
		return ret
	}

	return o.Data
}

// GetDataOk returns a tuple with the Data field value
// and a boolean to check if the value has been set.
func (o *BetaGroupBuildsLinkagesResponse) GetDataOk() ([]AppEncryptionDeclarationRelationshipsBuildsDataInner, bool) {
	if o == nil {
		return nil, false
	}
	return o.Data, true
}

// SetData sets field value
func (o *BetaGroupBuildsLinkagesResponse) SetData(v []AppEncryptionDeclarationRelationshipsBuildsDataInner) {
	o.Data = v
}

// GetLinks returns the Links field value
func (o *BetaGroupBuildsLinkagesResponse) GetLinks() PagedDocumentLinks {
	if o == nil {
		var ret PagedDocumentLinks
		return ret
	}

	return o.Links
}

// GetLinksOk returns a tuple with the Links field value
// and a boolean to check if the value has been set.
func (o *BetaGroupBuildsLinkagesResponse) GetLinksOk() (*PagedDocumentLinks, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Links, true
}

// SetLinks sets field value
func (o *BetaGroupBuildsLinkagesResponse) SetLinks(v PagedDocumentLinks) {
	o.Links = v
}

// GetMeta returns the Meta field value if set, zero value otherwise.
func (o *BetaGroupBuildsLinkagesResponse) GetMeta() PagingInformation {
	if o == nil || IsNil(o.Meta) {
		var ret PagingInformation
		return ret
	}
	return *o.Meta
}

// GetMetaOk returns a tuple with the Meta field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *BetaGroupBuildsLinkagesResponse) GetMetaOk() (*PagingInformation, bool) {
	if o == nil || IsNil(o.Meta) {
		return nil, false
	}
	return o.Meta, true
}

// HasMeta returns a boolean if a field has been set.
func (o *BetaGroupBuildsLinkagesResponse) HasMeta() bool {
	if o != nil && !IsNil(o.Meta) {
		return true
	}

	return false
}

// SetMeta gets a reference to the given PagingInformation and assigns it to the Meta field.
func (o *BetaGroupBuildsLinkagesResponse) SetMeta(v PagingInformation) {
	o.Meta = &v
}

func (o BetaGroupBuildsLinkagesResponse) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o BetaGroupBuildsLinkagesResponse) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["data"] = o.Data
	toSerialize["links"] = o.Links
	if !IsNil(o.Meta) {
		toSerialize["meta"] = o.Meta
	}
	return toSerialize, nil
}

type NullableBetaGroupBuildsLinkagesResponse struct {
	value *BetaGroupBuildsLinkagesResponse
	isSet bool
}

func (v NullableBetaGroupBuildsLinkagesResponse) Get() *BetaGroupBuildsLinkagesResponse {
	return v.value
}

func (v *NullableBetaGroupBuildsLinkagesResponse) Set(val *BetaGroupBuildsLinkagesResponse) {
	v.value = val
	v.isSet = true
}

func (v NullableBetaGroupBuildsLinkagesResponse) IsSet() bool {
	return v.isSet
}

func (v *NullableBetaGroupBuildsLinkagesResponse) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableBetaGroupBuildsLinkagesResponse(val *BetaGroupBuildsLinkagesResponse) *NullableBetaGroupBuildsLinkagesResponse {
	return &NullableBetaGroupBuildsLinkagesResponse{value: val, isSet: true}
}

func (v NullableBetaGroupBuildsLinkagesResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableBetaGroupBuildsLinkagesResponse) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}