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

// checks if the SubscriptionLocalizationUpdateRequestData type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &SubscriptionLocalizationUpdateRequestData{}

// SubscriptionLocalizationUpdateRequestData struct for SubscriptionLocalizationUpdateRequestData
type SubscriptionLocalizationUpdateRequestData struct {
	Type       string                                                `json:"type"`
	Id         string                                                `json:"id"`
	Attributes *InAppPurchaseLocalizationUpdateRequestDataAttributes `json:"attributes,omitempty"`
}

// NewSubscriptionLocalizationUpdateRequestData instantiates a new SubscriptionLocalizationUpdateRequestData object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewSubscriptionLocalizationUpdateRequestData(type_ string, id string) *SubscriptionLocalizationUpdateRequestData {
	this := SubscriptionLocalizationUpdateRequestData{}
	this.Type = type_
	this.Id = id
	return &this
}

// NewSubscriptionLocalizationUpdateRequestDataWithDefaults instantiates a new SubscriptionLocalizationUpdateRequestData object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewSubscriptionLocalizationUpdateRequestDataWithDefaults() *SubscriptionLocalizationUpdateRequestData {
	this := SubscriptionLocalizationUpdateRequestData{}
	return &this
}

// GetType returns the Type field value
func (o *SubscriptionLocalizationUpdateRequestData) GetType() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Type
}

// GetTypeOk returns a tuple with the Type field value
// and a boolean to check if the value has been set.
func (o *SubscriptionLocalizationUpdateRequestData) GetTypeOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Type, true
}

// SetType sets field value
func (o *SubscriptionLocalizationUpdateRequestData) SetType(v string) {
	o.Type = v
}

// GetId returns the Id field value
func (o *SubscriptionLocalizationUpdateRequestData) GetId() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Id
}

// GetIdOk returns a tuple with the Id field value
// and a boolean to check if the value has been set.
func (o *SubscriptionLocalizationUpdateRequestData) GetIdOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Id, true
}

// SetId sets field value
func (o *SubscriptionLocalizationUpdateRequestData) SetId(v string) {
	o.Id = v
}

// GetAttributes returns the Attributes field value if set, zero value otherwise.
func (o *SubscriptionLocalizationUpdateRequestData) GetAttributes() InAppPurchaseLocalizationUpdateRequestDataAttributes {
	if o == nil || IsNil(o.Attributes) {
		var ret InAppPurchaseLocalizationUpdateRequestDataAttributes
		return ret
	}
	return *o.Attributes
}

// GetAttributesOk returns a tuple with the Attributes field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *SubscriptionLocalizationUpdateRequestData) GetAttributesOk() (*InAppPurchaseLocalizationUpdateRequestDataAttributes, bool) {
	if o == nil || IsNil(o.Attributes) {
		return nil, false
	}
	return o.Attributes, true
}

// HasAttributes returns a boolean if a field has been set.
func (o *SubscriptionLocalizationUpdateRequestData) HasAttributes() bool {
	if o != nil && !IsNil(o.Attributes) {
		return true
	}

	return false
}

// SetAttributes gets a reference to the given InAppPurchaseLocalizationUpdateRequestDataAttributes and assigns it to the Attributes field.
func (o *SubscriptionLocalizationUpdateRequestData) SetAttributes(v InAppPurchaseLocalizationUpdateRequestDataAttributes) {
	o.Attributes = &v
}

func (o SubscriptionLocalizationUpdateRequestData) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o SubscriptionLocalizationUpdateRequestData) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["type"] = o.Type
	toSerialize["id"] = o.Id
	if !IsNil(o.Attributes) {
		toSerialize["attributes"] = o.Attributes
	}
	return toSerialize, nil
}

type NullableSubscriptionLocalizationUpdateRequestData struct {
	value *SubscriptionLocalizationUpdateRequestData
	isSet bool
}

func (v NullableSubscriptionLocalizationUpdateRequestData) Get() *SubscriptionLocalizationUpdateRequestData {
	return v.value
}

func (v *NullableSubscriptionLocalizationUpdateRequestData) Set(val *SubscriptionLocalizationUpdateRequestData) {
	v.value = val
	v.isSet = true
}

func (v NullableSubscriptionLocalizationUpdateRequestData) IsSet() bool {
	return v.isSet
}

func (v *NullableSubscriptionLocalizationUpdateRequestData) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableSubscriptionLocalizationUpdateRequestData(val *SubscriptionLocalizationUpdateRequestData) *NullableSubscriptionLocalizationUpdateRequestData {
	return &NullableSubscriptionLocalizationUpdateRequestData{value: val, isSet: true}
}

func (v NullableSubscriptionLocalizationUpdateRequestData) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableSubscriptionLocalizationUpdateRequestData) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
