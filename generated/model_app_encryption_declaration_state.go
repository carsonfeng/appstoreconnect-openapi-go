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

// AppEncryptionDeclarationState the model 'AppEncryptionDeclarationState'
type AppEncryptionDeclarationState string

// List of AppEncryptionDeclarationState
const (
	CREATED   AppEncryptionDeclarationState = "CREATED"
	IN_REVIEW AppEncryptionDeclarationState = "IN_REVIEW"
	APPROVED  AppEncryptionDeclarationState = "APPROVED"
	REJECTED  AppEncryptionDeclarationState = "REJECTED"
	INVALID   AppEncryptionDeclarationState = "INVALID"
	EXPIRED   AppEncryptionDeclarationState = "EXPIRED"
)

// All allowed values of AppEncryptionDeclarationState enum
var AllowedAppEncryptionDeclarationStateEnumValues = []AppEncryptionDeclarationState{
	"CREATED",
	"IN_REVIEW",
	"APPROVED",
	"REJECTED",
	"INVALID",
	"EXPIRED",
}

func (v *AppEncryptionDeclarationState) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := AppEncryptionDeclarationState(value)
	for _, existing := range AllowedAppEncryptionDeclarationStateEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid AppEncryptionDeclarationState", value)
}

// NewAppEncryptionDeclarationStateFromValue returns a pointer to a valid AppEncryptionDeclarationState
// for the value passed as argument, or an error if the value passed is not allowed by the enum
func NewAppEncryptionDeclarationStateFromValue(v string) (*AppEncryptionDeclarationState, error) {
	ev := AppEncryptionDeclarationState(v)
	if ev.IsValid() {
		return &ev, nil
	} else {
		return nil, fmt.Errorf("invalid value '%v' for AppEncryptionDeclarationState: valid values are %v", v, AllowedAppEncryptionDeclarationStateEnumValues)
	}
}

// IsValid return true if the value is valid for the enum, false otherwise
func (v AppEncryptionDeclarationState) IsValid() bool {
	for _, existing := range AllowedAppEncryptionDeclarationStateEnumValues {
		if existing == v {
			return true
		}
	}
	return false
}

// Ptr returns reference to AppEncryptionDeclarationState value
func (v AppEncryptionDeclarationState) Ptr() *AppEncryptionDeclarationState {
	return &v
}

type NullableAppEncryptionDeclarationState struct {
	value *AppEncryptionDeclarationState
	isSet bool
}

func (v NullableAppEncryptionDeclarationState) Get() *AppEncryptionDeclarationState {
	return v.value
}

func (v *NullableAppEncryptionDeclarationState) Set(val *AppEncryptionDeclarationState) {
	v.value = val
	v.isSet = true
}

func (v NullableAppEncryptionDeclarationState) IsSet() bool {
	return v.isSet
}

func (v *NullableAppEncryptionDeclarationState) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableAppEncryptionDeclarationState(val *AppEncryptionDeclarationState) *NullableAppEncryptionDeclarationState {
	return &NullableAppEncryptionDeclarationState{value: val, isSet: true}
}

func (v NullableAppEncryptionDeclarationState) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableAppEncryptionDeclarationState) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}