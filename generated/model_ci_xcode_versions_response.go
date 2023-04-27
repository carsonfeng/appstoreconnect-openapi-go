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

// checks if the CiXcodeVersionsResponse type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &CiXcodeVersionsResponse{}

// CiXcodeVersionsResponse struct for CiXcodeVersionsResponse
type CiXcodeVersionsResponse struct {
	Data     []CiXcodeVersion   `json:"data"`
	Included []CiMacOsVersion   `json:"included,omitempty"`
	Links    PagedDocumentLinks `json:"links"`
	Meta     *PagingInformation `json:"meta,omitempty"`
}

// NewCiXcodeVersionsResponse instantiates a new CiXcodeVersionsResponse object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewCiXcodeVersionsResponse(data []CiXcodeVersion, links PagedDocumentLinks) *CiXcodeVersionsResponse {
	this := CiXcodeVersionsResponse{}
	this.Data = data
	this.Links = links
	return &this
}

// NewCiXcodeVersionsResponseWithDefaults instantiates a new CiXcodeVersionsResponse object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewCiXcodeVersionsResponseWithDefaults() *CiXcodeVersionsResponse {
	this := CiXcodeVersionsResponse{}
	return &this
}

// GetData returns the Data field value
func (o *CiXcodeVersionsResponse) GetData() []CiXcodeVersion {
	if o == nil {
		var ret []CiXcodeVersion
		return ret
	}

	return o.Data
}

// GetDataOk returns a tuple with the Data field value
// and a boolean to check if the value has been set.
func (o *CiXcodeVersionsResponse) GetDataOk() ([]CiXcodeVersion, bool) {
	if o == nil {
		return nil, false
	}
	return o.Data, true
}

// SetData sets field value
func (o *CiXcodeVersionsResponse) SetData(v []CiXcodeVersion) {
	o.Data = v
}

// GetIncluded returns the Included field value if set, zero value otherwise.
func (o *CiXcodeVersionsResponse) GetIncluded() []CiMacOsVersion {
	if o == nil || IsNil(o.Included) {
		var ret []CiMacOsVersion
		return ret
	}
	return o.Included
}

// GetIncludedOk returns a tuple with the Included field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CiXcodeVersionsResponse) GetIncludedOk() ([]CiMacOsVersion, bool) {
	if o == nil || IsNil(o.Included) {
		return nil, false
	}
	return o.Included, true
}

// HasIncluded returns a boolean if a field has been set.
func (o *CiXcodeVersionsResponse) HasIncluded() bool {
	if o != nil && !IsNil(o.Included) {
		return true
	}

	return false
}

// SetIncluded gets a reference to the given []CiMacOsVersion and assigns it to the Included field.
func (o *CiXcodeVersionsResponse) SetIncluded(v []CiMacOsVersion) {
	o.Included = v
}

// GetLinks returns the Links field value
func (o *CiXcodeVersionsResponse) GetLinks() PagedDocumentLinks {
	if o == nil {
		var ret PagedDocumentLinks
		return ret
	}

	return o.Links
}

// GetLinksOk returns a tuple with the Links field value
// and a boolean to check if the value has been set.
func (o *CiXcodeVersionsResponse) GetLinksOk() (*PagedDocumentLinks, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Links, true
}

// SetLinks sets field value
func (o *CiXcodeVersionsResponse) SetLinks(v PagedDocumentLinks) {
	o.Links = v
}

// GetMeta returns the Meta field value if set, zero value otherwise.
func (o *CiXcodeVersionsResponse) GetMeta() PagingInformation {
	if o == nil || IsNil(o.Meta) {
		var ret PagingInformation
		return ret
	}
	return *o.Meta
}

// GetMetaOk returns a tuple with the Meta field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CiXcodeVersionsResponse) GetMetaOk() (*PagingInformation, bool) {
	if o == nil || IsNil(o.Meta) {
		return nil, false
	}
	return o.Meta, true
}

// HasMeta returns a boolean if a field has been set.
func (o *CiXcodeVersionsResponse) HasMeta() bool {
	if o != nil && !IsNil(o.Meta) {
		return true
	}

	return false
}

// SetMeta gets a reference to the given PagingInformation and assigns it to the Meta field.
func (o *CiXcodeVersionsResponse) SetMeta(v PagingInformation) {
	o.Meta = &v
}

func (o CiXcodeVersionsResponse) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o CiXcodeVersionsResponse) ToMap() (map[string]interface{}, error) {
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

type NullableCiXcodeVersionsResponse struct {
	value *CiXcodeVersionsResponse
	isSet bool
}

func (v NullableCiXcodeVersionsResponse) Get() *CiXcodeVersionsResponse {
	return v.value
}

func (v *NullableCiXcodeVersionsResponse) Set(val *CiXcodeVersionsResponse) {
	v.value = val
	v.isSet = true
}

func (v NullableCiXcodeVersionsResponse) IsSet() bool {
	return v.isSet
}

func (v *NullableCiXcodeVersionsResponse) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableCiXcodeVersionsResponse(val *CiXcodeVersionsResponse) *NullableCiXcodeVersionsResponse {
	return &NullableCiXcodeVersionsResponse{value: val, isSet: true}
}

func (v NullableCiXcodeVersionsResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableCiXcodeVersionsResponse) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
