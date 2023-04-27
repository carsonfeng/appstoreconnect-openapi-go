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

// checks if the SubscriptionPricePointInlineCreate type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &SubscriptionPricePointInlineCreate{}

// SubscriptionPricePointInlineCreate struct for SubscriptionPricePointInlineCreate
type SubscriptionPricePointInlineCreate struct {
	Type string  `json:"type"`
	Id   *string `json:"id,omitempty"`
}

// NewSubscriptionPricePointInlineCreate instantiates a new SubscriptionPricePointInlineCreate object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewSubscriptionPricePointInlineCreate(type_ string) *SubscriptionPricePointInlineCreate {
	this := SubscriptionPricePointInlineCreate{}
	this.Type = type_
	return &this
}

// NewSubscriptionPricePointInlineCreateWithDefaults instantiates a new SubscriptionPricePointInlineCreate object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewSubscriptionPricePointInlineCreateWithDefaults() *SubscriptionPricePointInlineCreate {
	this := SubscriptionPricePointInlineCreate{}
	return &this
}

// GetType returns the Type field value
func (o *SubscriptionPricePointInlineCreate) GetType() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Type
}

// GetTypeOk returns a tuple with the Type field value
// and a boolean to check if the value has been set.
func (o *SubscriptionPricePointInlineCreate) GetTypeOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Type, true
}

// SetType sets field value
func (o *SubscriptionPricePointInlineCreate) SetType(v string) {
	o.Type = v
}

// GetId returns the Id field value if set, zero value otherwise.
func (o *SubscriptionPricePointInlineCreate) GetId() string {
	if o == nil || IsNil(o.Id) {
		var ret string
		return ret
	}
	return *o.Id
}

// GetIdOk returns a tuple with the Id field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *SubscriptionPricePointInlineCreate) GetIdOk() (*string, bool) {
	if o == nil || IsNil(o.Id) {
		return nil, false
	}
	return o.Id, true
}

// HasId returns a boolean if a field has been set.
func (o *SubscriptionPricePointInlineCreate) HasId() bool {
	if o != nil && !IsNil(o.Id) {
		return true
	}

	return false
}

// SetId gets a reference to the given string and assigns it to the Id field.
func (o *SubscriptionPricePointInlineCreate) SetId(v string) {
	o.Id = &v
}

func (o SubscriptionPricePointInlineCreate) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o SubscriptionPricePointInlineCreate) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["type"] = o.Type
	if !IsNil(o.Id) {
		toSerialize["id"] = o.Id
	}
	return toSerialize, nil
}

type NullableSubscriptionPricePointInlineCreate struct {
	value *SubscriptionPricePointInlineCreate
	isSet bool
}

func (v NullableSubscriptionPricePointInlineCreate) Get() *SubscriptionPricePointInlineCreate {
	return v.value
}

func (v *NullableSubscriptionPricePointInlineCreate) Set(val *SubscriptionPricePointInlineCreate) {
	v.value = val
	v.isSet = true
}

func (v NullableSubscriptionPricePointInlineCreate) IsSet() bool {
	return v.isSet
}

func (v *NullableSubscriptionPricePointInlineCreate) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableSubscriptionPricePointInlineCreate(val *SubscriptionPricePointInlineCreate) *NullableSubscriptionPricePointInlineCreate {
	return &NullableSubscriptionPricePointInlineCreate{value: val, isSet: true}
}

func (v NullableSubscriptionPricePointInlineCreate) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableSubscriptionPricePointInlineCreate) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
