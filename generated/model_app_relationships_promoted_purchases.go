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

// checks if the AppRelationshipsPromotedPurchases type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &AppRelationshipsPromotedPurchases{}

// AppRelationshipsPromotedPurchases struct for AppRelationshipsPromotedPurchases
type AppRelationshipsPromotedPurchases struct {
	Links *AppAvailabilityRelationshipsAppLinks        `json:"links,omitempty"`
	Meta  *PagingInformation                           `json:"meta,omitempty"`
	Data  []AppRelationshipsPromotedPurchasesDataInner `json:"data,omitempty"`
}

// NewAppRelationshipsPromotedPurchases instantiates a new AppRelationshipsPromotedPurchases object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewAppRelationshipsPromotedPurchases() *AppRelationshipsPromotedPurchases {
	this := AppRelationshipsPromotedPurchases{}
	return &this
}

// NewAppRelationshipsPromotedPurchasesWithDefaults instantiates a new AppRelationshipsPromotedPurchases object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAppRelationshipsPromotedPurchasesWithDefaults() *AppRelationshipsPromotedPurchases {
	this := AppRelationshipsPromotedPurchases{}
	return &this
}

// GetLinks returns the Links field value if set, zero value otherwise.
func (o *AppRelationshipsPromotedPurchases) GetLinks() AppAvailabilityRelationshipsAppLinks {
	if o == nil || IsNil(o.Links) {
		var ret AppAvailabilityRelationshipsAppLinks
		return ret
	}
	return *o.Links
}

// GetLinksOk returns a tuple with the Links field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AppRelationshipsPromotedPurchases) GetLinksOk() (*AppAvailabilityRelationshipsAppLinks, bool) {
	if o == nil || IsNil(o.Links) {
		return nil, false
	}
	return o.Links, true
}

// HasLinks returns a boolean if a field has been set.
func (o *AppRelationshipsPromotedPurchases) HasLinks() bool {
	if o != nil && !IsNil(o.Links) {
		return true
	}

	return false
}

// SetLinks gets a reference to the given AppAvailabilityRelationshipsAppLinks and assigns it to the Links field.
func (o *AppRelationshipsPromotedPurchases) SetLinks(v AppAvailabilityRelationshipsAppLinks) {
	o.Links = &v
}

// GetMeta returns the Meta field value if set, zero value otherwise.
func (o *AppRelationshipsPromotedPurchases) GetMeta() PagingInformation {
	if o == nil || IsNil(o.Meta) {
		var ret PagingInformation
		return ret
	}
	return *o.Meta
}

// GetMetaOk returns a tuple with the Meta field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AppRelationshipsPromotedPurchases) GetMetaOk() (*PagingInformation, bool) {
	if o == nil || IsNil(o.Meta) {
		return nil, false
	}
	return o.Meta, true
}

// HasMeta returns a boolean if a field has been set.
func (o *AppRelationshipsPromotedPurchases) HasMeta() bool {
	if o != nil && !IsNil(o.Meta) {
		return true
	}

	return false
}

// SetMeta gets a reference to the given PagingInformation and assigns it to the Meta field.
func (o *AppRelationshipsPromotedPurchases) SetMeta(v PagingInformation) {
	o.Meta = &v
}

// GetData returns the Data field value if set, zero value otherwise.
func (o *AppRelationshipsPromotedPurchases) GetData() []AppRelationshipsPromotedPurchasesDataInner {
	if o == nil || IsNil(o.Data) {
		var ret []AppRelationshipsPromotedPurchasesDataInner
		return ret
	}
	return o.Data
}

// GetDataOk returns a tuple with the Data field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AppRelationshipsPromotedPurchases) GetDataOk() ([]AppRelationshipsPromotedPurchasesDataInner, bool) {
	if o == nil || IsNil(o.Data) {
		return nil, false
	}
	return o.Data, true
}

// HasData returns a boolean if a field has been set.
func (o *AppRelationshipsPromotedPurchases) HasData() bool {
	if o != nil && !IsNil(o.Data) {
		return true
	}

	return false
}

// SetData gets a reference to the given []AppRelationshipsPromotedPurchasesDataInner and assigns it to the Data field.
func (o *AppRelationshipsPromotedPurchases) SetData(v []AppRelationshipsPromotedPurchasesDataInner) {
	o.Data = v
}

func (o AppRelationshipsPromotedPurchases) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o AppRelationshipsPromotedPurchases) ToMap() (map[string]interface{}, error) {
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

type NullableAppRelationshipsPromotedPurchases struct {
	value *AppRelationshipsPromotedPurchases
	isSet bool
}

func (v NullableAppRelationshipsPromotedPurchases) Get() *AppRelationshipsPromotedPurchases {
	return v.value
}

func (v *NullableAppRelationshipsPromotedPurchases) Set(val *AppRelationshipsPromotedPurchases) {
	v.value = val
	v.isSet = true
}

func (v NullableAppRelationshipsPromotedPurchases) IsSet() bool {
	return v.isSet
}

func (v *NullableAppRelationshipsPromotedPurchases) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableAppRelationshipsPromotedPurchases(val *AppRelationshipsPromotedPurchases) *NullableAppRelationshipsPromotedPurchases {
	return &NullableAppRelationshipsPromotedPurchases{value: val, isSet: true}
}

func (v NullableAppRelationshipsPromotedPurchases) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableAppRelationshipsPromotedPurchases) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
