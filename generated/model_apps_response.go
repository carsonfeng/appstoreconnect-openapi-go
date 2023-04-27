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

// checks if the AppsResponse type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &AppsResponse{}

// AppsResponse struct for AppsResponse
type AppsResponse struct {
	Data     []App                       `json:"data"`
	Included []AppsResponseIncludedInner `json:"included,omitempty"`
	Links    PagedDocumentLinks          `json:"links"`
	Meta     *PagingInformation          `json:"meta,omitempty"`
}

// NewAppsResponse instantiates a new AppsResponse object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewAppsResponse(data []App, links PagedDocumentLinks) *AppsResponse {
	this := AppsResponse{}
	this.Data = data
	this.Links = links
	return &this
}

// NewAppsResponseWithDefaults instantiates a new AppsResponse object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAppsResponseWithDefaults() *AppsResponse {
	this := AppsResponse{}
	return &this
}

// GetData returns the Data field value
func (o *AppsResponse) GetData() []App {
	if o == nil {
		var ret []App
		return ret
	}

	return o.Data
}

// GetDataOk returns a tuple with the Data field value
// and a boolean to check if the value has been set.
func (o *AppsResponse) GetDataOk() ([]App, bool) {
	if o == nil {
		return nil, false
	}
	return o.Data, true
}

// SetData sets field value
func (o *AppsResponse) SetData(v []App) {
	o.Data = v
}

// GetIncluded returns the Included field value if set, zero value otherwise.
func (o *AppsResponse) GetIncluded() []AppsResponseIncludedInner {
	if o == nil || IsNil(o.Included) {
		var ret []AppsResponseIncludedInner
		return ret
	}
	return o.Included
}

// GetIncludedOk returns a tuple with the Included field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AppsResponse) GetIncludedOk() ([]AppsResponseIncludedInner, bool) {
	if o == nil || IsNil(o.Included) {
		return nil, false
	}
	return o.Included, true
}

// HasIncluded returns a boolean if a field has been set.
func (o *AppsResponse) HasIncluded() bool {
	if o != nil && !IsNil(o.Included) {
		return true
	}

	return false
}

// SetIncluded gets a reference to the given []AppsResponseIncludedInner and assigns it to the Included field.
func (o *AppsResponse) SetIncluded(v []AppsResponseIncludedInner) {
	o.Included = v
}

// GetLinks returns the Links field value
func (o *AppsResponse) GetLinks() PagedDocumentLinks {
	if o == nil {
		var ret PagedDocumentLinks
		return ret
	}

	return o.Links
}

// GetLinksOk returns a tuple with the Links field value
// and a boolean to check if the value has been set.
func (o *AppsResponse) GetLinksOk() (*PagedDocumentLinks, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Links, true
}

// SetLinks sets field value
func (o *AppsResponse) SetLinks(v PagedDocumentLinks) {
	o.Links = v
}

// GetMeta returns the Meta field value if set, zero value otherwise.
func (o *AppsResponse) GetMeta() PagingInformation {
	if o == nil || IsNil(o.Meta) {
		var ret PagingInformation
		return ret
	}
	return *o.Meta
}

// GetMetaOk returns a tuple with the Meta field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AppsResponse) GetMetaOk() (*PagingInformation, bool) {
	if o == nil || IsNil(o.Meta) {
		return nil, false
	}
	return o.Meta, true
}

// HasMeta returns a boolean if a field has been set.
func (o *AppsResponse) HasMeta() bool {
	if o != nil && !IsNil(o.Meta) {
		return true
	}

	return false
}

// SetMeta gets a reference to the given PagingInformation and assigns it to the Meta field.
func (o *AppsResponse) SetMeta(v PagingInformation) {
	o.Meta = &v
}

func (o AppsResponse) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o AppsResponse) ToMap() (map[string]interface{}, error) {
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

type NullableAppsResponse struct {
	value *AppsResponse
	isSet bool
}

func (v NullableAppsResponse) Get() *AppsResponse {
	return v.value
}

func (v *NullableAppsResponse) Set(val *AppsResponse) {
	v.value = val
	v.isSet = true
}

func (v NullableAppsResponse) IsSet() bool {
	return v.isSet
}

func (v *NullableAppsResponse) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableAppsResponse(val *AppsResponse) *NullableAppsResponse {
	return &NullableAppsResponse{value: val, isSet: true}
}

func (v NullableAppsResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableAppsResponse) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
