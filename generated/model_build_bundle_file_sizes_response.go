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

// checks if the BuildBundleFileSizesResponse type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &BuildBundleFileSizesResponse{}

// BuildBundleFileSizesResponse struct for BuildBundleFileSizesResponse
type BuildBundleFileSizesResponse struct {
	Data  []BuildBundleFileSize `json:"data"`
	Links PagedDocumentLinks    `json:"links"`
	Meta  *PagingInformation    `json:"meta,omitempty"`
}

// NewBuildBundleFileSizesResponse instantiates a new BuildBundleFileSizesResponse object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewBuildBundleFileSizesResponse(data []BuildBundleFileSize, links PagedDocumentLinks) *BuildBundleFileSizesResponse {
	this := BuildBundleFileSizesResponse{}
	this.Data = data
	this.Links = links
	return &this
}

// NewBuildBundleFileSizesResponseWithDefaults instantiates a new BuildBundleFileSizesResponse object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewBuildBundleFileSizesResponseWithDefaults() *BuildBundleFileSizesResponse {
	this := BuildBundleFileSizesResponse{}
	return &this
}

// GetData returns the Data field value
func (o *BuildBundleFileSizesResponse) GetData() []BuildBundleFileSize {
	if o == nil {
		var ret []BuildBundleFileSize
		return ret
	}

	return o.Data
}

// GetDataOk returns a tuple with the Data field value
// and a boolean to check if the value has been set.
func (o *BuildBundleFileSizesResponse) GetDataOk() ([]BuildBundleFileSize, bool) {
	if o == nil {
		return nil, false
	}
	return o.Data, true
}

// SetData sets field value
func (o *BuildBundleFileSizesResponse) SetData(v []BuildBundleFileSize) {
	o.Data = v
}

// GetLinks returns the Links field value
func (o *BuildBundleFileSizesResponse) GetLinks() PagedDocumentLinks {
	if o == nil {
		var ret PagedDocumentLinks
		return ret
	}

	return o.Links
}

// GetLinksOk returns a tuple with the Links field value
// and a boolean to check if the value has been set.
func (o *BuildBundleFileSizesResponse) GetLinksOk() (*PagedDocumentLinks, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Links, true
}

// SetLinks sets field value
func (o *BuildBundleFileSizesResponse) SetLinks(v PagedDocumentLinks) {
	o.Links = v
}

// GetMeta returns the Meta field value if set, zero value otherwise.
func (o *BuildBundleFileSizesResponse) GetMeta() PagingInformation {
	if o == nil || IsNil(o.Meta) {
		var ret PagingInformation
		return ret
	}
	return *o.Meta
}

// GetMetaOk returns a tuple with the Meta field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *BuildBundleFileSizesResponse) GetMetaOk() (*PagingInformation, bool) {
	if o == nil || IsNil(o.Meta) {
		return nil, false
	}
	return o.Meta, true
}

// HasMeta returns a boolean if a field has been set.
func (o *BuildBundleFileSizesResponse) HasMeta() bool {
	if o != nil && !IsNil(o.Meta) {
		return true
	}

	return false
}

// SetMeta gets a reference to the given PagingInformation and assigns it to the Meta field.
func (o *BuildBundleFileSizesResponse) SetMeta(v PagingInformation) {
	o.Meta = &v
}

func (o BuildBundleFileSizesResponse) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o BuildBundleFileSizesResponse) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["data"] = o.Data
	toSerialize["links"] = o.Links
	if !IsNil(o.Meta) {
		toSerialize["meta"] = o.Meta
	}
	return toSerialize, nil
}

type NullableBuildBundleFileSizesResponse struct {
	value *BuildBundleFileSizesResponse
	isSet bool
}

func (v NullableBuildBundleFileSizesResponse) Get() *BuildBundleFileSizesResponse {
	return v.value
}

func (v *NullableBuildBundleFileSizesResponse) Set(val *BuildBundleFileSizesResponse) {
	v.value = val
	v.isSet = true
}

func (v NullableBuildBundleFileSizesResponse) IsSet() bool {
	return v.isSet
}

func (v *NullableBuildBundleFileSizesResponse) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableBuildBundleFileSizesResponse(val *BuildBundleFileSizesResponse) *NullableBuildBundleFileSizesResponse {
	return &NullableBuildBundleFileSizesResponse{value: val, isSet: true}
}

func (v NullableBuildBundleFileSizesResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableBuildBundleFileSizesResponse) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
