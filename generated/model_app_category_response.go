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

// checks if the AppCategoryResponse type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &AppCategoryResponse{}

// AppCategoryResponse struct for AppCategoryResponse
type AppCategoryResponse struct {
	Data     AppCategory                          `json:"data"`
	Included []AppCategoriesResponseIncludedInner `json:"included,omitempty"`
	Links    DocumentLinks                        `json:"links"`
}

// NewAppCategoryResponse instantiates a new AppCategoryResponse object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewAppCategoryResponse(data AppCategory, links DocumentLinks) *AppCategoryResponse {
	this := AppCategoryResponse{}
	this.Data = data
	this.Links = links
	return &this
}

// NewAppCategoryResponseWithDefaults instantiates a new AppCategoryResponse object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAppCategoryResponseWithDefaults() *AppCategoryResponse {
	this := AppCategoryResponse{}
	return &this
}

// GetData returns the Data field value
func (o *AppCategoryResponse) GetData() AppCategory {
	if o == nil {
		var ret AppCategory
		return ret
	}

	return o.Data
}

// GetDataOk returns a tuple with the Data field value
// and a boolean to check if the value has been set.
func (o *AppCategoryResponse) GetDataOk() (*AppCategory, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Data, true
}

// SetData sets field value
func (o *AppCategoryResponse) SetData(v AppCategory) {
	o.Data = v
}

// GetIncluded returns the Included field value if set, zero value otherwise.
func (o *AppCategoryResponse) GetIncluded() []AppCategoriesResponseIncludedInner {
	if o == nil || IsNil(o.Included) {
		var ret []AppCategoriesResponseIncludedInner
		return ret
	}
	return o.Included
}

// GetIncludedOk returns a tuple with the Included field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AppCategoryResponse) GetIncludedOk() ([]AppCategoriesResponseIncludedInner, bool) {
	if o == nil || IsNil(o.Included) {
		return nil, false
	}
	return o.Included, true
}

// HasIncluded returns a boolean if a field has been set.
func (o *AppCategoryResponse) HasIncluded() bool {
	if o != nil && !IsNil(o.Included) {
		return true
	}

	return false
}

// SetIncluded gets a reference to the given []AppCategoriesResponseIncludedInner and assigns it to the Included field.
func (o *AppCategoryResponse) SetIncluded(v []AppCategoriesResponseIncludedInner) {
	o.Included = v
}

// GetLinks returns the Links field value
func (o *AppCategoryResponse) GetLinks() DocumentLinks {
	if o == nil {
		var ret DocumentLinks
		return ret
	}

	return o.Links
}

// GetLinksOk returns a tuple with the Links field value
// and a boolean to check if the value has been set.
func (o *AppCategoryResponse) GetLinksOk() (*DocumentLinks, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Links, true
}

// SetLinks sets field value
func (o *AppCategoryResponse) SetLinks(v DocumentLinks) {
	o.Links = v
}

func (o AppCategoryResponse) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o AppCategoryResponse) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["data"] = o.Data
	if !IsNil(o.Included) {
		toSerialize["included"] = o.Included
	}
	toSerialize["links"] = o.Links
	return toSerialize, nil
}

type NullableAppCategoryResponse struct {
	value *AppCategoryResponse
	isSet bool
}

func (v NullableAppCategoryResponse) Get() *AppCategoryResponse {
	return v.value
}

func (v *NullableAppCategoryResponse) Set(val *AppCategoryResponse) {
	v.value = val
	v.isSet = true
}

func (v NullableAppCategoryResponse) IsSet() bool {
	return v.isSet
}

func (v *NullableAppCategoryResponse) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableAppCategoryResponse(val *AppCategoryResponse) *NullableAppCategoryResponse {
	return &NullableAppCategoryResponse{value: val, isSet: true}
}

func (v NullableAppCategoryResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableAppCategoryResponse) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
