/*
App Store Connect API

No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)

API version: 2.3
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package openapi

import (
	"encoding/json"
	"fmt"
)

// SubscriptionOfferDuration the model 'SubscriptionOfferDuration'
type SubscriptionOfferDuration string

// List of SubscriptionOfferDuration
const (
	ONE_DAY SubscriptionOfferDuration = "ONE_DAY"
	//THREE_DAYS   SubscriptionOfferDuration = "THREE_DAYS"
	ONE_WEEK     SubscriptionOfferDuration = "ONE_WEEK"
	TWO_WEEKS    SubscriptionOfferDuration = "TWO_WEEKS"
	ONE_MONTH    SubscriptionOfferDuration = "ONE_MONTH"
	TWO_MONTHS   SubscriptionOfferDuration = "TWO_MONTHS"
	THREE_MONTHS SubscriptionOfferDuration = "THREE_MONTHS"
	SIX_MONTHS   SubscriptionOfferDuration = "SIX_MONTHS"
	ONE_YEAR     SubscriptionOfferDuration = "ONE_YEAR"
)

// All allowed values of SubscriptionOfferDuration enum
var AllowedSubscriptionOfferDurationEnumValues = []SubscriptionOfferDuration{
	"ONE_DAY",
	"THREE_DAYS",
	"ONE_WEEK",
	"TWO_WEEKS",
	"ONE_MONTH",
	"TWO_MONTHS",
	"THREE_MONTHS",
	"SIX_MONTHS",
	"ONE_YEAR",
}

func (v *SubscriptionOfferDuration) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := SubscriptionOfferDuration(value)
	for _, existing := range AllowedSubscriptionOfferDurationEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid SubscriptionOfferDuration", value)
}

// NewSubscriptionOfferDurationFromValue returns a pointer to a valid SubscriptionOfferDuration
// for the value passed as argument, or an error if the value passed is not allowed by the enum
func NewSubscriptionOfferDurationFromValue(v string) (*SubscriptionOfferDuration, error) {
	ev := SubscriptionOfferDuration(v)
	if ev.IsValid() {
		return &ev, nil
	} else {
		return nil, fmt.Errorf("invalid value '%v' for SubscriptionOfferDuration: valid values are %v", v, AllowedSubscriptionOfferDurationEnumValues)
	}
}

// IsValid return true if the value is valid for the enum, false otherwise
func (v SubscriptionOfferDuration) IsValid() bool {
	for _, existing := range AllowedSubscriptionOfferDurationEnumValues {
		if existing == v {
			return true
		}
	}
	return false
}

// Ptr returns reference to SubscriptionOfferDuration value
func (v SubscriptionOfferDuration) Ptr() *SubscriptionOfferDuration {
	return &v
}

type NullableSubscriptionOfferDuration struct {
	value *SubscriptionOfferDuration
	isSet bool
}

func (v NullableSubscriptionOfferDuration) Get() *SubscriptionOfferDuration {
	return v.value
}

func (v *NullableSubscriptionOfferDuration) Set(val *SubscriptionOfferDuration) {
	v.value = val
	v.isSet = true
}

func (v NullableSubscriptionOfferDuration) IsSet() bool {
	return v.isSet
}

func (v *NullableSubscriptionOfferDuration) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableSubscriptionOfferDuration(val *SubscriptionOfferDuration) *NullableSubscriptionOfferDuration {
	return &NullableSubscriptionOfferDuration{value: val, isSet: true}
}

func (v NullableSubscriptionOfferDuration) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableSubscriptionOfferDuration) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
