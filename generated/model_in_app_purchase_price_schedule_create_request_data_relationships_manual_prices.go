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

// checks if the InAppPurchasePriceScheduleCreateRequestDataRelationshipsManualPrices type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &InAppPurchasePriceScheduleCreateRequestDataRelationshipsManualPrices{}

// InAppPurchasePriceScheduleCreateRequestDataRelationshipsManualPrices struct for InAppPurchasePriceScheduleCreateRequestDataRelationshipsManualPrices
type InAppPurchasePriceScheduleCreateRequestDataRelationshipsManualPrices struct {
	Data []InAppPurchasePriceScheduleRelationshipsManualPricesDataInner `json:"data"`
}

// NewInAppPurchasePriceScheduleCreateRequestDataRelationshipsManualPrices instantiates a new InAppPurchasePriceScheduleCreateRequestDataRelationshipsManualPrices object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewInAppPurchasePriceScheduleCreateRequestDataRelationshipsManualPrices(data []InAppPurchasePriceScheduleRelationshipsManualPricesDataInner) *InAppPurchasePriceScheduleCreateRequestDataRelationshipsManualPrices {
	this := InAppPurchasePriceScheduleCreateRequestDataRelationshipsManualPrices{}
	this.Data = data
	return &this
}

// NewInAppPurchasePriceScheduleCreateRequestDataRelationshipsManualPricesWithDefaults instantiates a new InAppPurchasePriceScheduleCreateRequestDataRelationshipsManualPrices object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewInAppPurchasePriceScheduleCreateRequestDataRelationshipsManualPricesWithDefaults() *InAppPurchasePriceScheduleCreateRequestDataRelationshipsManualPrices {
	this := InAppPurchasePriceScheduleCreateRequestDataRelationshipsManualPrices{}
	return &this
}

// GetData returns the Data field value
func (o *InAppPurchasePriceScheduleCreateRequestDataRelationshipsManualPrices) GetData() []InAppPurchasePriceScheduleRelationshipsManualPricesDataInner {
	if o == nil {
		var ret []InAppPurchasePriceScheduleRelationshipsManualPricesDataInner
		return ret
	}

	return o.Data
}

// GetDataOk returns a tuple with the Data field value
// and a boolean to check if the value has been set.
func (o *InAppPurchasePriceScheduleCreateRequestDataRelationshipsManualPrices) GetDataOk() ([]InAppPurchasePriceScheduleRelationshipsManualPricesDataInner, bool) {
	if o == nil {
		return nil, false
	}
	return o.Data, true
}

// SetData sets field value
func (o *InAppPurchasePriceScheduleCreateRequestDataRelationshipsManualPrices) SetData(v []InAppPurchasePriceScheduleRelationshipsManualPricesDataInner) {
	o.Data = v
}

func (o InAppPurchasePriceScheduleCreateRequestDataRelationshipsManualPrices) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o InAppPurchasePriceScheduleCreateRequestDataRelationshipsManualPrices) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["data"] = o.Data
	return toSerialize, nil
}

type NullableInAppPurchasePriceScheduleCreateRequestDataRelationshipsManualPrices struct {
	value *InAppPurchasePriceScheduleCreateRequestDataRelationshipsManualPrices
	isSet bool
}

func (v NullableInAppPurchasePriceScheduleCreateRequestDataRelationshipsManualPrices) Get() *InAppPurchasePriceScheduleCreateRequestDataRelationshipsManualPrices {
	return v.value
}

func (v *NullableInAppPurchasePriceScheduleCreateRequestDataRelationshipsManualPrices) Set(val *InAppPurchasePriceScheduleCreateRequestDataRelationshipsManualPrices) {
	v.value = val
	v.isSet = true
}

func (v NullableInAppPurchasePriceScheduleCreateRequestDataRelationshipsManualPrices) IsSet() bool {
	return v.isSet
}

func (v *NullableInAppPurchasePriceScheduleCreateRequestDataRelationshipsManualPrices) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableInAppPurchasePriceScheduleCreateRequestDataRelationshipsManualPrices(val *InAppPurchasePriceScheduleCreateRequestDataRelationshipsManualPrices) *NullableInAppPurchasePriceScheduleCreateRequestDataRelationshipsManualPrices {
	return &NullableInAppPurchasePriceScheduleCreateRequestDataRelationshipsManualPrices{value: val, isSet: true}
}

func (v NullableInAppPurchasePriceScheduleCreateRequestDataRelationshipsManualPrices) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableInAppPurchasePriceScheduleCreateRequestDataRelationshipsManualPrices) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
