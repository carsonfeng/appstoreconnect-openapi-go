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

// checks if the SubscriptionPriceCreateRequest type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &SubscriptionPriceCreateRequest{}

// SubscriptionPriceCreateRequest struct for SubscriptionPriceCreateRequest
type SubscriptionPriceCreateRequest struct {
	Data SubscriptionPriceCreateRequestData `json:"data"`
}

// NewSubscriptionPriceCreateRequest instantiates a new SubscriptionPriceCreateRequest object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewSubscriptionPriceCreateRequest(data SubscriptionPriceCreateRequestData) *SubscriptionPriceCreateRequest {
	this := SubscriptionPriceCreateRequest{}
	this.Data = data
	return &this
}

// NewSubscriptionPriceCreateRequestWithDefaults instantiates a new SubscriptionPriceCreateRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewSubscriptionPriceCreateRequestWithDefaults() *SubscriptionPriceCreateRequest {
	this := SubscriptionPriceCreateRequest{}
	return &this
}

// GetData returns the Data field value
func (o *SubscriptionPriceCreateRequest) GetData() SubscriptionPriceCreateRequestData {
	if o == nil {
		var ret SubscriptionPriceCreateRequestData
		return ret
	}

	return o.Data
}

// GetDataOk returns a tuple with the Data field value
// and a boolean to check if the value has been set.
func (o *SubscriptionPriceCreateRequest) GetDataOk() (*SubscriptionPriceCreateRequestData, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Data, true
}

// SetData sets field value
func (o *SubscriptionPriceCreateRequest) SetData(v SubscriptionPriceCreateRequestData) {
	o.Data = v
}

func (o SubscriptionPriceCreateRequest) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o SubscriptionPriceCreateRequest) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["data"] = o.Data
	return toSerialize, nil
}

type NullableSubscriptionPriceCreateRequest struct {
	value *SubscriptionPriceCreateRequest
	isSet bool
}

func (v NullableSubscriptionPriceCreateRequest) Get() *SubscriptionPriceCreateRequest {
	return v.value
}

func (v *NullableSubscriptionPriceCreateRequest) Set(val *SubscriptionPriceCreateRequest) {
	v.value = val
	v.isSet = true
}

func (v NullableSubscriptionPriceCreateRequest) IsSet() bool {
	return v.isSet
}

func (v *NullableSubscriptionPriceCreateRequest) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableSubscriptionPriceCreateRequest(val *SubscriptionPriceCreateRequest) *NullableSubscriptionPriceCreateRequest {
	return &NullableSubscriptionPriceCreateRequest{value: val, isSet: true}
}

func (v NullableSubscriptionPriceCreateRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableSubscriptionPriceCreateRequest) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
