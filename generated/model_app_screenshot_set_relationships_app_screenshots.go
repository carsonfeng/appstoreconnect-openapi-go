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

// checks if the AppScreenshotSetRelationshipsAppScreenshots type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &AppScreenshotSetRelationshipsAppScreenshots{}

// AppScreenshotSetRelationshipsAppScreenshots struct for AppScreenshotSetRelationshipsAppScreenshots
type AppScreenshotSetRelationshipsAppScreenshots struct {
	Links *AppAvailabilityRelationshipsAppLinks                  `json:"links,omitempty"`
	Meta  *PagingInformation                                     `json:"meta,omitempty"`
	Data  []AppScreenshotSetRelationshipsAppScreenshotsDataInner `json:"data,omitempty"`
}

// NewAppScreenshotSetRelationshipsAppScreenshots instantiates a new AppScreenshotSetRelationshipsAppScreenshots object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewAppScreenshotSetRelationshipsAppScreenshots() *AppScreenshotSetRelationshipsAppScreenshots {
	this := AppScreenshotSetRelationshipsAppScreenshots{}
	return &this
}

// NewAppScreenshotSetRelationshipsAppScreenshotsWithDefaults instantiates a new AppScreenshotSetRelationshipsAppScreenshots object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAppScreenshotSetRelationshipsAppScreenshotsWithDefaults() *AppScreenshotSetRelationshipsAppScreenshots {
	this := AppScreenshotSetRelationshipsAppScreenshots{}
	return &this
}

// GetLinks returns the Links field value if set, zero value otherwise.
func (o *AppScreenshotSetRelationshipsAppScreenshots) GetLinks() AppAvailabilityRelationshipsAppLinks {
	if o == nil || IsNil(o.Links) {
		var ret AppAvailabilityRelationshipsAppLinks
		return ret
	}
	return *o.Links
}

// GetLinksOk returns a tuple with the Links field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AppScreenshotSetRelationshipsAppScreenshots) GetLinksOk() (*AppAvailabilityRelationshipsAppLinks, bool) {
	if o == nil || IsNil(o.Links) {
		return nil, false
	}
	return o.Links, true
}

// HasLinks returns a boolean if a field has been set.
func (o *AppScreenshotSetRelationshipsAppScreenshots) HasLinks() bool {
	if o != nil && !IsNil(o.Links) {
		return true
	}

	return false
}

// SetLinks gets a reference to the given AppAvailabilityRelationshipsAppLinks and assigns it to the Links field.
func (o *AppScreenshotSetRelationshipsAppScreenshots) SetLinks(v AppAvailabilityRelationshipsAppLinks) {
	o.Links = &v
}

// GetMeta returns the Meta field value if set, zero value otherwise.
func (o *AppScreenshotSetRelationshipsAppScreenshots) GetMeta() PagingInformation {
	if o == nil || IsNil(o.Meta) {
		var ret PagingInformation
		return ret
	}
	return *o.Meta
}

// GetMetaOk returns a tuple with the Meta field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AppScreenshotSetRelationshipsAppScreenshots) GetMetaOk() (*PagingInformation, bool) {
	if o == nil || IsNil(o.Meta) {
		return nil, false
	}
	return o.Meta, true
}

// HasMeta returns a boolean if a field has been set.
func (o *AppScreenshotSetRelationshipsAppScreenshots) HasMeta() bool {
	if o != nil && !IsNil(o.Meta) {
		return true
	}

	return false
}

// SetMeta gets a reference to the given PagingInformation and assigns it to the Meta field.
func (o *AppScreenshotSetRelationshipsAppScreenshots) SetMeta(v PagingInformation) {
	o.Meta = &v
}

// GetData returns the Data field value if set, zero value otherwise.
func (o *AppScreenshotSetRelationshipsAppScreenshots) GetData() []AppScreenshotSetRelationshipsAppScreenshotsDataInner {
	if o == nil || IsNil(o.Data) {
		var ret []AppScreenshotSetRelationshipsAppScreenshotsDataInner
		return ret
	}
	return o.Data
}

// GetDataOk returns a tuple with the Data field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AppScreenshotSetRelationshipsAppScreenshots) GetDataOk() ([]AppScreenshotSetRelationshipsAppScreenshotsDataInner, bool) {
	if o == nil || IsNil(o.Data) {
		return nil, false
	}
	return o.Data, true
}

// HasData returns a boolean if a field has been set.
func (o *AppScreenshotSetRelationshipsAppScreenshots) HasData() bool {
	if o != nil && !IsNil(o.Data) {
		return true
	}

	return false
}

// SetData gets a reference to the given []AppScreenshotSetRelationshipsAppScreenshotsDataInner and assigns it to the Data field.
func (o *AppScreenshotSetRelationshipsAppScreenshots) SetData(v []AppScreenshotSetRelationshipsAppScreenshotsDataInner) {
	o.Data = v
}

func (o AppScreenshotSetRelationshipsAppScreenshots) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o AppScreenshotSetRelationshipsAppScreenshots) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.Links) {
		toSerialize["links"] = o.Links
	}
	if !IsNil(o.Meta) {
		toSerialize["meta"] = o.Meta
	}
	if !IsNil(o.Data) {
		toSerialize["data"] = o.Data
	}
	return toSerialize, nil
}

type NullableAppScreenshotSetRelationshipsAppScreenshots struct {
	value *AppScreenshotSetRelationshipsAppScreenshots
	isSet bool
}

func (v NullableAppScreenshotSetRelationshipsAppScreenshots) Get() *AppScreenshotSetRelationshipsAppScreenshots {
	return v.value
}

func (v *NullableAppScreenshotSetRelationshipsAppScreenshots) Set(val *AppScreenshotSetRelationshipsAppScreenshots) {
	v.value = val
	v.isSet = true
}

func (v NullableAppScreenshotSetRelationshipsAppScreenshots) IsSet() bool {
	return v.isSet
}

func (v *NullableAppScreenshotSetRelationshipsAppScreenshots) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableAppScreenshotSetRelationshipsAppScreenshots(val *AppScreenshotSetRelationshipsAppScreenshots) *NullableAppScreenshotSetRelationshipsAppScreenshots {
	return &NullableAppScreenshotSetRelationshipsAppScreenshots{value: val, isSet: true}
}

func (v NullableAppScreenshotSetRelationshipsAppScreenshots) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableAppScreenshotSetRelationshipsAppScreenshots) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
