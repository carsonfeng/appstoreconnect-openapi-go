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

// checks if the InAppPurchaseV2RelationshipsInAppPurchaseLocalizationsDataInner type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &InAppPurchaseV2RelationshipsInAppPurchaseLocalizationsDataInner{}

// InAppPurchaseV2RelationshipsInAppPurchaseLocalizationsDataInner struct for InAppPurchaseV2RelationshipsInAppPurchaseLocalizationsDataInner
type InAppPurchaseV2RelationshipsInAppPurchaseLocalizationsDataInner struct {
	Type string `json:"type"`
	Id   string `json:"id"`
}

// NewInAppPurchaseV2RelationshipsInAppPurchaseLocalizationsDataInner instantiates a new InAppPurchaseV2RelationshipsInAppPurchaseLocalizationsDataInner object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewInAppPurchaseV2RelationshipsInAppPurchaseLocalizationsDataInner(type_ string, id string) *InAppPurchaseV2RelationshipsInAppPurchaseLocalizationsDataInner {
	this := InAppPurchaseV2RelationshipsInAppPurchaseLocalizationsDataInner{}
	this.Type = type_
	this.Id = id
	return &this
}

// NewInAppPurchaseV2RelationshipsInAppPurchaseLocalizationsDataInnerWithDefaults instantiates a new InAppPurchaseV2RelationshipsInAppPurchaseLocalizationsDataInner object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewInAppPurchaseV2RelationshipsInAppPurchaseLocalizationsDataInnerWithDefaults() *InAppPurchaseV2RelationshipsInAppPurchaseLocalizationsDataInner {
	this := InAppPurchaseV2RelationshipsInAppPurchaseLocalizationsDataInner{}
	return &this
}

// GetType returns the Type field value
func (o *InAppPurchaseV2RelationshipsInAppPurchaseLocalizationsDataInner) GetType() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Type
}

// GetTypeOk returns a tuple with the Type field value
// and a boolean to check if the value has been set.
func (o *InAppPurchaseV2RelationshipsInAppPurchaseLocalizationsDataInner) GetTypeOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Type, true
}

// SetType sets field value
func (o *InAppPurchaseV2RelationshipsInAppPurchaseLocalizationsDataInner) SetType(v string) {
	o.Type = v
}

// GetId returns the Id field value
func (o *InAppPurchaseV2RelationshipsInAppPurchaseLocalizationsDataInner) GetId() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Id
}

// GetIdOk returns a tuple with the Id field value
// and a boolean to check if the value has been set.
func (o *InAppPurchaseV2RelationshipsInAppPurchaseLocalizationsDataInner) GetIdOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Id, true
}

// SetId sets field value
func (o *InAppPurchaseV2RelationshipsInAppPurchaseLocalizationsDataInner) SetId(v string) {
	o.Id = v
}

func (o InAppPurchaseV2RelationshipsInAppPurchaseLocalizationsDataInner) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o InAppPurchaseV2RelationshipsInAppPurchaseLocalizationsDataInner) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["type"] = o.Type
	toSerialize["id"] = o.Id
	return toSerialize, nil
}

type NullableInAppPurchaseV2RelationshipsInAppPurchaseLocalizationsDataInner struct {
	value *InAppPurchaseV2RelationshipsInAppPurchaseLocalizationsDataInner
	isSet bool
}

func (v NullableInAppPurchaseV2RelationshipsInAppPurchaseLocalizationsDataInner) Get() *InAppPurchaseV2RelationshipsInAppPurchaseLocalizationsDataInner {
	return v.value
}

func (v *NullableInAppPurchaseV2RelationshipsInAppPurchaseLocalizationsDataInner) Set(val *InAppPurchaseV2RelationshipsInAppPurchaseLocalizationsDataInner) {
	v.value = val
	v.isSet = true
}

func (v NullableInAppPurchaseV2RelationshipsInAppPurchaseLocalizationsDataInner) IsSet() bool {
	return v.isSet
}

func (v *NullableInAppPurchaseV2RelationshipsInAppPurchaseLocalizationsDataInner) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableInAppPurchaseV2RelationshipsInAppPurchaseLocalizationsDataInner(val *InAppPurchaseV2RelationshipsInAppPurchaseLocalizationsDataInner) *NullableInAppPurchaseV2RelationshipsInAppPurchaseLocalizationsDataInner {
	return &NullableInAppPurchaseV2RelationshipsInAppPurchaseLocalizationsDataInner{value: val, isSet: true}
}

func (v NullableInAppPurchaseV2RelationshipsInAppPurchaseLocalizationsDataInner) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableInAppPurchaseV2RelationshipsInAppPurchaseLocalizationsDataInner) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
