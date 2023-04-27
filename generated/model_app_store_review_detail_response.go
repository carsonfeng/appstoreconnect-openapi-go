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

// checks if the AppStoreReviewDetailResponse type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &AppStoreReviewDetailResponse{}

// AppStoreReviewDetailResponse struct for AppStoreReviewDetailResponse
type AppStoreReviewDetailResponse struct {
	Data     AppStoreReviewDetail                        `json:"data"`
	Included []AppStoreReviewDetailResponseIncludedInner `json:"included,omitempty"`
	Links    DocumentLinks                               `json:"links"`
}

// NewAppStoreReviewDetailResponse instantiates a new AppStoreReviewDetailResponse object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewAppStoreReviewDetailResponse(data AppStoreReviewDetail, links DocumentLinks) *AppStoreReviewDetailResponse {
	this := AppStoreReviewDetailResponse{}
	this.Data = data
	this.Links = links
	return &this
}

// NewAppStoreReviewDetailResponseWithDefaults instantiates a new AppStoreReviewDetailResponse object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAppStoreReviewDetailResponseWithDefaults() *AppStoreReviewDetailResponse {
	this := AppStoreReviewDetailResponse{}
	return &this
}

// GetData returns the Data field value
func (o *AppStoreReviewDetailResponse) GetData() AppStoreReviewDetail {
	if o == nil {
		var ret AppStoreReviewDetail
		return ret
	}

	return o.Data
}

// GetDataOk returns a tuple with the Data field value
// and a boolean to check if the value has been set.
func (o *AppStoreReviewDetailResponse) GetDataOk() (*AppStoreReviewDetail, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Data, true
}

// SetData sets field value
func (o *AppStoreReviewDetailResponse) SetData(v AppStoreReviewDetail) {
	o.Data = v
}

// GetIncluded returns the Included field value if set, zero value otherwise.
func (o *AppStoreReviewDetailResponse) GetIncluded() []AppStoreReviewDetailResponseIncludedInner {
	if o == nil || IsNil(o.Included) {
		var ret []AppStoreReviewDetailResponseIncludedInner
		return ret
	}
	return o.Included
}

// GetIncludedOk returns a tuple with the Included field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AppStoreReviewDetailResponse) GetIncludedOk() ([]AppStoreReviewDetailResponseIncludedInner, bool) {
	if o == nil || IsNil(o.Included) {
		return nil, false
	}
	return o.Included, true
}

// HasIncluded returns a boolean if a field has been set.
func (o *AppStoreReviewDetailResponse) HasIncluded() bool {
	if o != nil && !IsNil(o.Included) {
		return true
	}

	return false
}

// SetIncluded gets a reference to the given []AppStoreReviewDetailResponseIncludedInner and assigns it to the Included field.
func (o *AppStoreReviewDetailResponse) SetIncluded(v []AppStoreReviewDetailResponseIncludedInner) {
	o.Included = v
}

// GetLinks returns the Links field value
func (o *AppStoreReviewDetailResponse) GetLinks() DocumentLinks {
	if o == nil {
		var ret DocumentLinks
		return ret
	}

	return o.Links
}

// GetLinksOk returns a tuple with the Links field value
// and a boolean to check if the value has been set.
func (o *AppStoreReviewDetailResponse) GetLinksOk() (*DocumentLinks, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Links, true
}

// SetLinks sets field value
func (o *AppStoreReviewDetailResponse) SetLinks(v DocumentLinks) {
	o.Links = v
}

func (o AppStoreReviewDetailResponse) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o AppStoreReviewDetailResponse) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["data"] = o.Data
	if !IsNil(o.Included) {
		toSerialize["included"] = o.Included
	}
	toSerialize["links"] = o.Links
	return toSerialize, nil
}

type NullableAppStoreReviewDetailResponse struct {
	value *AppStoreReviewDetailResponse
	isSet bool
}

func (v NullableAppStoreReviewDetailResponse) Get() *AppStoreReviewDetailResponse {
	return v.value
}

func (v *NullableAppStoreReviewDetailResponse) Set(val *AppStoreReviewDetailResponse) {
	v.value = val
	v.isSet = true
}

func (v NullableAppStoreReviewDetailResponse) IsSet() bool {
	return v.isSet
}

func (v *NullableAppStoreReviewDetailResponse) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableAppStoreReviewDetailResponse(val *AppStoreReviewDetailResponse) *NullableAppStoreReviewDetailResponse {
	return &NullableAppStoreReviewDetailResponse{value: val, isSet: true}
}

func (v NullableAppStoreReviewDetailResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableAppStoreReviewDetailResponse) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}