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

// checks if the AppCustomProductPageLocalizationResponse type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &AppCustomProductPageLocalizationResponse{}

// AppCustomProductPageLocalizationResponse struct for AppCustomProductPageLocalizationResponse
type AppCustomProductPageLocalizationResponse struct {
	Data     AppCustomProductPageLocalization                         `json:"data"`
	Included []AppCustomProductPageLocalizationsResponseIncludedInner `json:"included,omitempty"`
	Links    DocumentLinks                                            `json:"links"`
}

// NewAppCustomProductPageLocalizationResponse instantiates a new AppCustomProductPageLocalizationResponse object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewAppCustomProductPageLocalizationResponse(data AppCustomProductPageLocalization, links DocumentLinks) *AppCustomProductPageLocalizationResponse {
	this := AppCustomProductPageLocalizationResponse{}
	this.Data = data
	this.Links = links
	return &this
}

// NewAppCustomProductPageLocalizationResponseWithDefaults instantiates a new AppCustomProductPageLocalizationResponse object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAppCustomProductPageLocalizationResponseWithDefaults() *AppCustomProductPageLocalizationResponse {
	this := AppCustomProductPageLocalizationResponse{}
	return &this
}

// GetData returns the Data field value
func (o *AppCustomProductPageLocalizationResponse) GetData() AppCustomProductPageLocalization {
	if o == nil {
		var ret AppCustomProductPageLocalization
		return ret
	}

	return o.Data
}

// GetDataOk returns a tuple with the Data field value
// and a boolean to check if the value has been set.
func (o *AppCustomProductPageLocalizationResponse) GetDataOk() (*AppCustomProductPageLocalization, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Data, true
}

// SetData sets field value
func (o *AppCustomProductPageLocalizationResponse) SetData(v AppCustomProductPageLocalization) {
	o.Data = v
}

// GetIncluded returns the Included field value if set, zero value otherwise.
func (o *AppCustomProductPageLocalizationResponse) GetIncluded() []AppCustomProductPageLocalizationsResponseIncludedInner {
	if o == nil || IsNil(o.Included) {
		var ret []AppCustomProductPageLocalizationsResponseIncludedInner
		return ret
	}
	return o.Included
}

// GetIncludedOk returns a tuple with the Included field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AppCustomProductPageLocalizationResponse) GetIncludedOk() ([]AppCustomProductPageLocalizationsResponseIncludedInner, bool) {
	if o == nil || IsNil(o.Included) {
		return nil, false
	}
	return o.Included, true
}

// HasIncluded returns a boolean if a field has been set.
func (o *AppCustomProductPageLocalizationResponse) HasIncluded() bool {
	if o != nil && !IsNil(o.Included) {
		return true
	}

	return false
}

// SetIncluded gets a reference to the given []AppCustomProductPageLocalizationsResponseIncludedInner and assigns it to the Included field.
func (o *AppCustomProductPageLocalizationResponse) SetIncluded(v []AppCustomProductPageLocalizationsResponseIncludedInner) {
	o.Included = v
}

// GetLinks returns the Links field value
func (o *AppCustomProductPageLocalizationResponse) GetLinks() DocumentLinks {
	if o == nil {
		var ret DocumentLinks
		return ret
	}

	return o.Links
}

// GetLinksOk returns a tuple with the Links field value
// and a boolean to check if the value has been set.
func (o *AppCustomProductPageLocalizationResponse) GetLinksOk() (*DocumentLinks, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Links, true
}

// SetLinks sets field value
func (o *AppCustomProductPageLocalizationResponse) SetLinks(v DocumentLinks) {
	o.Links = v
}

func (o AppCustomProductPageLocalizationResponse) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o AppCustomProductPageLocalizationResponse) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["data"] = o.Data
	if !IsNil(o.Included) {
		toSerialize["included"] = o.Included
	}
	toSerialize["links"] = o.Links
	return toSerialize, nil
}

type NullableAppCustomProductPageLocalizationResponse struct {
	value *AppCustomProductPageLocalizationResponse
	isSet bool
}

func (v NullableAppCustomProductPageLocalizationResponse) Get() *AppCustomProductPageLocalizationResponse {
	return v.value
}

func (v *NullableAppCustomProductPageLocalizationResponse) Set(val *AppCustomProductPageLocalizationResponse) {
	v.value = val
	v.isSet = true
}

func (v NullableAppCustomProductPageLocalizationResponse) IsSet() bool {
	return v.isSet
}

func (v *NullableAppCustomProductPageLocalizationResponse) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableAppCustomProductPageLocalizationResponse(val *AppCustomProductPageLocalizationResponse) *NullableAppCustomProductPageLocalizationResponse {
	return &NullableAppCustomProductPageLocalizationResponse{value: val, isSet: true}
}

func (v NullableAppCustomProductPageLocalizationResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableAppCustomProductPageLocalizationResponse) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
