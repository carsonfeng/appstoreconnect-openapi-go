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

// checks if the BetaBuildLocalizationAttributes type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &BetaBuildLocalizationAttributes{}

// BetaBuildLocalizationAttributes struct for BetaBuildLocalizationAttributes
type BetaBuildLocalizationAttributes struct {
	WhatsNew *string `json:"whatsNew,omitempty"`
	Locale   *string `json:"locale,omitempty"`
}

// NewBetaBuildLocalizationAttributes instantiates a new BetaBuildLocalizationAttributes object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewBetaBuildLocalizationAttributes() *BetaBuildLocalizationAttributes {
	this := BetaBuildLocalizationAttributes{}
	return &this
}

// NewBetaBuildLocalizationAttributesWithDefaults instantiates a new BetaBuildLocalizationAttributes object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewBetaBuildLocalizationAttributesWithDefaults() *BetaBuildLocalizationAttributes {
	this := BetaBuildLocalizationAttributes{}
	return &this
}

// GetWhatsNew returns the WhatsNew field value if set, zero value otherwise.
func (o *BetaBuildLocalizationAttributes) GetWhatsNew() string {
	if o == nil || IsNil(o.WhatsNew) {
		var ret string
		return ret
	}
	return *o.WhatsNew
}

// GetWhatsNewOk returns a tuple with the WhatsNew field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *BetaBuildLocalizationAttributes) GetWhatsNewOk() (*string, bool) {
	if o == nil || IsNil(o.WhatsNew) {
		return nil, false
	}
	return o.WhatsNew, true
}

// HasWhatsNew returns a boolean if a field has been set.
func (o *BetaBuildLocalizationAttributes) HasWhatsNew() bool {
	if o != nil && !IsNil(o.WhatsNew) {
		return true
	}

	return false
}

// SetWhatsNew gets a reference to the given string and assigns it to the WhatsNew field.
func (o *BetaBuildLocalizationAttributes) SetWhatsNew(v string) {
	o.WhatsNew = &v
}

// GetLocale returns the Locale field value if set, zero value otherwise.
func (o *BetaBuildLocalizationAttributes) GetLocale() string {
	if o == nil || IsNil(o.Locale) {
		var ret string
		return ret
	}
	return *o.Locale
}

// GetLocaleOk returns a tuple with the Locale field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *BetaBuildLocalizationAttributes) GetLocaleOk() (*string, bool) {
	if o == nil || IsNil(o.Locale) {
		return nil, false
	}
	return o.Locale, true
}

// HasLocale returns a boolean if a field has been set.
func (o *BetaBuildLocalizationAttributes) HasLocale() bool {
	if o != nil && !IsNil(o.Locale) {
		return true
	}

	return false
}

// SetLocale gets a reference to the given string and assigns it to the Locale field.
func (o *BetaBuildLocalizationAttributes) SetLocale(v string) {
	o.Locale = &v
}

func (o BetaBuildLocalizationAttributes) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o BetaBuildLocalizationAttributes) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.WhatsNew) {
		toSerialize["whatsNew"] = o.WhatsNew
	}
	if !IsNil(o.Locale) {
		toSerialize["locale"] = o.Locale
	}
	return toSerialize, nil
}

type NullableBetaBuildLocalizationAttributes struct {
	value *BetaBuildLocalizationAttributes
	isSet bool
}

func (v NullableBetaBuildLocalizationAttributes) Get() *BetaBuildLocalizationAttributes {
	return v.value
}

func (v *NullableBetaBuildLocalizationAttributes) Set(val *BetaBuildLocalizationAttributes) {
	v.value = val
	v.isSet = true
}

func (v NullableBetaBuildLocalizationAttributes) IsSet() bool {
	return v.isSet
}

func (v *NullableBetaBuildLocalizationAttributes) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableBetaBuildLocalizationAttributes(val *BetaBuildLocalizationAttributes) *NullableBetaBuildLocalizationAttributes {
	return &NullableBetaBuildLocalizationAttributes{value: val, isSet: true}
}

func (v NullableBetaBuildLocalizationAttributes) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableBetaBuildLocalizationAttributes) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}