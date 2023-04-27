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

// checks if the SubscriptionIntroductoryOfferRelationshipsSubscriptionPricePointData type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &SubscriptionIntroductoryOfferRelationshipsSubscriptionPricePointData{}

// SubscriptionIntroductoryOfferRelationshipsSubscriptionPricePointData struct for SubscriptionIntroductoryOfferRelationshipsSubscriptionPricePointData
type SubscriptionIntroductoryOfferRelationshipsSubscriptionPricePointData struct {
	Type string `json:"type"`
	Id   string `json:"id"`
}

// NewSubscriptionIntroductoryOfferRelationshipsSubscriptionPricePointData instantiates a new SubscriptionIntroductoryOfferRelationshipsSubscriptionPricePointData object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewSubscriptionIntroductoryOfferRelationshipsSubscriptionPricePointData(type_ string, id string) *SubscriptionIntroductoryOfferRelationshipsSubscriptionPricePointData {
	this := SubscriptionIntroductoryOfferRelationshipsSubscriptionPricePointData{}
	this.Type = type_
	this.Id = id
	return &this
}

// NewSubscriptionIntroductoryOfferRelationshipsSubscriptionPricePointDataWithDefaults instantiates a new SubscriptionIntroductoryOfferRelationshipsSubscriptionPricePointData object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewSubscriptionIntroductoryOfferRelationshipsSubscriptionPricePointDataWithDefaults() *SubscriptionIntroductoryOfferRelationshipsSubscriptionPricePointData {
	this := SubscriptionIntroductoryOfferRelationshipsSubscriptionPricePointData{}
	return &this
}

// GetType returns the Type field value
func (o *SubscriptionIntroductoryOfferRelationshipsSubscriptionPricePointData) GetType() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Type
}

// GetTypeOk returns a tuple with the Type field value
// and a boolean to check if the value has been set.
func (o *SubscriptionIntroductoryOfferRelationshipsSubscriptionPricePointData) GetTypeOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Type, true
}

// SetType sets field value
func (o *SubscriptionIntroductoryOfferRelationshipsSubscriptionPricePointData) SetType(v string) {
	o.Type = v
}

// GetId returns the Id field value
func (o *SubscriptionIntroductoryOfferRelationshipsSubscriptionPricePointData) GetId() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Id
}

// GetIdOk returns a tuple with the Id field value
// and a boolean to check if the value has been set.
func (o *SubscriptionIntroductoryOfferRelationshipsSubscriptionPricePointData) GetIdOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Id, true
}

// SetId sets field value
func (o *SubscriptionIntroductoryOfferRelationshipsSubscriptionPricePointData) SetId(v string) {
	o.Id = v
}

func (o SubscriptionIntroductoryOfferRelationshipsSubscriptionPricePointData) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o SubscriptionIntroductoryOfferRelationshipsSubscriptionPricePointData) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["type"] = o.Type
	toSerialize["id"] = o.Id
	return toSerialize, nil
}

type NullableSubscriptionIntroductoryOfferRelationshipsSubscriptionPricePointData struct {
	value *SubscriptionIntroductoryOfferRelationshipsSubscriptionPricePointData
	isSet bool
}

func (v NullableSubscriptionIntroductoryOfferRelationshipsSubscriptionPricePointData) Get() *SubscriptionIntroductoryOfferRelationshipsSubscriptionPricePointData {
	return v.value
}

func (v *NullableSubscriptionIntroductoryOfferRelationshipsSubscriptionPricePointData) Set(val *SubscriptionIntroductoryOfferRelationshipsSubscriptionPricePointData) {
	v.value = val
	v.isSet = true
}

func (v NullableSubscriptionIntroductoryOfferRelationshipsSubscriptionPricePointData) IsSet() bool {
	return v.isSet
}

func (v *NullableSubscriptionIntroductoryOfferRelationshipsSubscriptionPricePointData) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableSubscriptionIntroductoryOfferRelationshipsSubscriptionPricePointData(val *SubscriptionIntroductoryOfferRelationshipsSubscriptionPricePointData) *NullableSubscriptionIntroductoryOfferRelationshipsSubscriptionPricePointData {
	return &NullableSubscriptionIntroductoryOfferRelationshipsSubscriptionPricePointData{value: val, isSet: true}
}

func (v NullableSubscriptionIntroductoryOfferRelationshipsSubscriptionPricePointData) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableSubscriptionIntroductoryOfferRelationshipsSubscriptionPricePointData) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
