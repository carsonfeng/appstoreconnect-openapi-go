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

// checks if the InAppPurchaseV2RelationshipsPromotedPurchase type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &InAppPurchaseV2RelationshipsPromotedPurchase{}

// InAppPurchaseV2RelationshipsPromotedPurchase struct for InAppPurchaseV2RelationshipsPromotedPurchase
type InAppPurchaseV2RelationshipsPromotedPurchase struct {
	Links *AppAvailabilityRelationshipsAppLinks       `json:"links,omitempty"`
	Data  *AppRelationshipsPromotedPurchasesDataInner `json:"data,omitempty"`
}

// NewInAppPurchaseV2RelationshipsPromotedPurchase instantiates a new InAppPurchaseV2RelationshipsPromotedPurchase object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewInAppPurchaseV2RelationshipsPromotedPurchase() *InAppPurchaseV2RelationshipsPromotedPurchase {
	this := InAppPurchaseV2RelationshipsPromotedPurchase{}
	return &this
}

// NewInAppPurchaseV2RelationshipsPromotedPurchaseWithDefaults instantiates a new InAppPurchaseV2RelationshipsPromotedPurchase object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewInAppPurchaseV2RelationshipsPromotedPurchaseWithDefaults() *InAppPurchaseV2RelationshipsPromotedPurchase {
	this := InAppPurchaseV2RelationshipsPromotedPurchase{}
	return &this
}

// GetLinks returns the Links field value if set, zero value otherwise.
func (o *InAppPurchaseV2RelationshipsPromotedPurchase) GetLinks() AppAvailabilityRelationshipsAppLinks {
	if o == nil || IsNil(o.Links) {
		var ret AppAvailabilityRelationshipsAppLinks
		return ret
	}
	return *o.Links
}

// GetLinksOk returns a tuple with the Links field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *InAppPurchaseV2RelationshipsPromotedPurchase) GetLinksOk() (*AppAvailabilityRelationshipsAppLinks, bool) {
	if o == nil || IsNil(o.Links) {
		return nil, false
	}
	return o.Links, true
}

// HasLinks returns a boolean if a field has been set.
func (o *InAppPurchaseV2RelationshipsPromotedPurchase) HasLinks() bool {
	if o != nil && !IsNil(o.Links) {
		return true
	}

	return false
}

// SetLinks gets a reference to the given AppAvailabilityRelationshipsAppLinks and assigns it to the Links field.
func (o *InAppPurchaseV2RelationshipsPromotedPurchase) SetLinks(v AppAvailabilityRelationshipsAppLinks) {
	o.Links = &v
}

// GetData returns the Data field value if set, zero value otherwise.
func (o *InAppPurchaseV2RelationshipsPromotedPurchase) GetData() AppRelationshipsPromotedPurchasesDataInner {
	if o == nil || IsNil(o.Data) {
		var ret AppRelationshipsPromotedPurchasesDataInner
		return ret
	}
	return *o.Data
}

// GetDataOk returns a tuple with the Data field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *InAppPurchaseV2RelationshipsPromotedPurchase) GetDataOk() (*AppRelationshipsPromotedPurchasesDataInner, bool) {
	if o == nil || IsNil(o.Data) {
		return nil, false
	}
	return o.Data, true
}

// HasData returns a boolean if a field has been set.
func (o *InAppPurchaseV2RelationshipsPromotedPurchase) HasData() bool {
	if o != nil && !IsNil(o.Data) {
		return true
	}

	return false
}

// SetData gets a reference to the given AppRelationshipsPromotedPurchasesDataInner and assigns it to the Data field.
func (o *InAppPurchaseV2RelationshipsPromotedPurchase) SetData(v AppRelationshipsPromotedPurchasesDataInner) {
	o.Data = &v
}

func (o InAppPurchaseV2RelationshipsPromotedPurchase) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o InAppPurchaseV2RelationshipsPromotedPurchase) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.Links) {
		toSerialize["links"] = o.Links
	}
	if !IsNil(o.Data) {
		toSerialize["data"] = o.Data
	}
	return toSerialize, nil
}

type NullableInAppPurchaseV2RelationshipsPromotedPurchase struct {
	value *InAppPurchaseV2RelationshipsPromotedPurchase
	isSet bool
}

func (v NullableInAppPurchaseV2RelationshipsPromotedPurchase) Get() *InAppPurchaseV2RelationshipsPromotedPurchase {
	return v.value
}

func (v *NullableInAppPurchaseV2RelationshipsPromotedPurchase) Set(val *InAppPurchaseV2RelationshipsPromotedPurchase) {
	v.value = val
	v.isSet = true
}

func (v NullableInAppPurchaseV2RelationshipsPromotedPurchase) IsSet() bool {
	return v.isSet
}

func (v *NullableInAppPurchaseV2RelationshipsPromotedPurchase) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableInAppPurchaseV2RelationshipsPromotedPurchase(val *InAppPurchaseV2RelationshipsPromotedPurchase) *NullableInAppPurchaseV2RelationshipsPromotedPurchase {
	return &NullableInAppPurchaseV2RelationshipsPromotedPurchase{value: val, isSet: true}
}

func (v NullableInAppPurchaseV2RelationshipsPromotedPurchase) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableInAppPurchaseV2RelationshipsPromotedPurchase) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
