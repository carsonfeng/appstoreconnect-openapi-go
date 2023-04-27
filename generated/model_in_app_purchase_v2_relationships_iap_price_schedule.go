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

// checks if the InAppPurchaseV2RelationshipsIapPriceSchedule type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &InAppPurchaseV2RelationshipsIapPriceSchedule{}

// InAppPurchaseV2RelationshipsIapPriceSchedule struct for InAppPurchaseV2RelationshipsIapPriceSchedule
type InAppPurchaseV2RelationshipsIapPriceSchedule struct {
	Links *AppAvailabilityRelationshipsAppLinks             `json:"links,omitempty"`
	Data  *InAppPurchaseV2RelationshipsIapPriceScheduleData `json:"data,omitempty"`
}

// NewInAppPurchaseV2RelationshipsIapPriceSchedule instantiates a new InAppPurchaseV2RelationshipsIapPriceSchedule object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewInAppPurchaseV2RelationshipsIapPriceSchedule() *InAppPurchaseV2RelationshipsIapPriceSchedule {
	this := InAppPurchaseV2RelationshipsIapPriceSchedule{}
	return &this
}

// NewInAppPurchaseV2RelationshipsIapPriceScheduleWithDefaults instantiates a new InAppPurchaseV2RelationshipsIapPriceSchedule object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewInAppPurchaseV2RelationshipsIapPriceScheduleWithDefaults() *InAppPurchaseV2RelationshipsIapPriceSchedule {
	this := InAppPurchaseV2RelationshipsIapPriceSchedule{}
	return &this
}

// GetLinks returns the Links field value if set, zero value otherwise.
func (o *InAppPurchaseV2RelationshipsIapPriceSchedule) GetLinks() AppAvailabilityRelationshipsAppLinks {
	if o == nil || IsNil(o.Links) {
		var ret AppAvailabilityRelationshipsAppLinks
		return ret
	}
	return *o.Links
}

// GetLinksOk returns a tuple with the Links field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *InAppPurchaseV2RelationshipsIapPriceSchedule) GetLinksOk() (*AppAvailabilityRelationshipsAppLinks, bool) {
	if o == nil || IsNil(o.Links) {
		return nil, false
	}
	return o.Links, true
}

// HasLinks returns a boolean if a field has been set.
func (o *InAppPurchaseV2RelationshipsIapPriceSchedule) HasLinks() bool {
	if o != nil && !IsNil(o.Links) {
		return true
	}

	return false
}

// SetLinks gets a reference to the given AppAvailabilityRelationshipsAppLinks and assigns it to the Links field.
func (o *InAppPurchaseV2RelationshipsIapPriceSchedule) SetLinks(v AppAvailabilityRelationshipsAppLinks) {
	o.Links = &v
}

// GetData returns the Data field value if set, zero value otherwise.
func (o *InAppPurchaseV2RelationshipsIapPriceSchedule) GetData() InAppPurchaseV2RelationshipsIapPriceScheduleData {
	if o == nil || IsNil(o.Data) {
		var ret InAppPurchaseV2RelationshipsIapPriceScheduleData
		return ret
	}
	return *o.Data
}

// GetDataOk returns a tuple with the Data field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *InAppPurchaseV2RelationshipsIapPriceSchedule) GetDataOk() (*InAppPurchaseV2RelationshipsIapPriceScheduleData, bool) {
	if o == nil || IsNil(o.Data) {
		return nil, false
	}
	return o.Data, true
}

// HasData returns a boolean if a field has been set.
func (o *InAppPurchaseV2RelationshipsIapPriceSchedule) HasData() bool {
	if o != nil && !IsNil(o.Data) {
		return true
	}

	return false
}

// SetData gets a reference to the given InAppPurchaseV2RelationshipsIapPriceScheduleData and assigns it to the Data field.
func (o *InAppPurchaseV2RelationshipsIapPriceSchedule) SetData(v InAppPurchaseV2RelationshipsIapPriceScheduleData) {
	o.Data = &v
}

func (o InAppPurchaseV2RelationshipsIapPriceSchedule) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o InAppPurchaseV2RelationshipsIapPriceSchedule) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.Links) {
		toSerialize["links"] = o.Links
	}
	if !IsNil(o.Data) {
		toSerialize["data"] = o.Data
	}
	return toSerialize, nil
}

type NullableInAppPurchaseV2RelationshipsIapPriceSchedule struct {
	value *InAppPurchaseV2RelationshipsIapPriceSchedule
	isSet bool
}

func (v NullableInAppPurchaseV2RelationshipsIapPriceSchedule) Get() *InAppPurchaseV2RelationshipsIapPriceSchedule {
	return v.value
}

func (v *NullableInAppPurchaseV2RelationshipsIapPriceSchedule) Set(val *InAppPurchaseV2RelationshipsIapPriceSchedule) {
	v.value = val
	v.isSet = true
}

func (v NullableInAppPurchaseV2RelationshipsIapPriceSchedule) IsSet() bool {
	return v.isSet
}

func (v *NullableInAppPurchaseV2RelationshipsIapPriceSchedule) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableInAppPurchaseV2RelationshipsIapPriceSchedule(val *InAppPurchaseV2RelationshipsIapPriceSchedule) *NullableInAppPurchaseV2RelationshipsIapPriceSchedule {
	return &NullableInAppPurchaseV2RelationshipsIapPriceSchedule{value: val, isSet: true}
}

func (v NullableInAppPurchaseV2RelationshipsIapPriceSchedule) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableInAppPurchaseV2RelationshipsIapPriceSchedule) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
