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

// PreviewType the model 'PreviewType'
type PreviewType string

// List of PreviewType
const (
	IPHONE_67          PreviewType = "IPHONE_67"
	IPHONE_61          PreviewType = "IPHONE_61"
	IPHONE_65          PreviewType = "IPHONE_65"
	IPHONE_58          PreviewType = "IPHONE_58"
	IPHONE_55          PreviewType = "IPHONE_55"
	IPHONE_47          PreviewType = "IPHONE_47"
	IPHONE_40          PreviewType = "IPHONE_40"
	IPHONE_35          PreviewType = "IPHONE_35"
	IPAD_PRO_3_GEN_129 PreviewType = "IPAD_PRO_3GEN_129"
	IPAD_PRO_3_GEN_11  PreviewType = "IPAD_PRO_3GEN_11"
	IPAD_PRO_129       PreviewType = "IPAD_PRO_129"
	IPAD_105           PreviewType = "IPAD_105"
	IPAD_97            PreviewType = "IPAD_97"
	DESKTOP            PreviewType = "DESKTOP"
	APPLE_TV           PreviewType = "APPLE_TV"
)

// All allowed values of PreviewType enum
var AllowedPreviewTypeEnumValues = []PreviewType{
	"IPHONE_67",
	"IPHONE_61",
	"IPHONE_65",
	"IPHONE_58",
	"IPHONE_55",
	"IPHONE_47",
	"IPHONE_40",
	"IPHONE_35",
	"IPAD_PRO_3GEN_129",
	"IPAD_PRO_3GEN_11",
	"IPAD_PRO_129",
	"IPAD_105",
	"IPAD_97",
	"DESKTOP",
	"APPLE_TV",
}

func (v *PreviewType) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := PreviewType(value)
	for _, existing := range AllowedPreviewTypeEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid PreviewType", value)
}

// NewPreviewTypeFromValue returns a pointer to a valid PreviewType
// for the value passed as argument, or an error if the value passed is not allowed by the enum
func NewPreviewTypeFromValue(v string) (*PreviewType, error) {
	ev := PreviewType(v)
	if ev.IsValid() {
		return &ev, nil
	} else {
		return nil, fmt.Errorf("invalid value '%v' for PreviewType: valid values are %v", v, AllowedPreviewTypeEnumValues)
	}
}

// IsValid return true if the value is valid for the enum, false otherwise
func (v PreviewType) IsValid() bool {
	for _, existing := range AllowedPreviewTypeEnumValues {
		if existing == v {
			return true
		}
	}
	return false
}

// Ptr returns reference to PreviewType value
func (v PreviewType) Ptr() *PreviewType {
	return &v
}

type NullablePreviewType struct {
	value *PreviewType
	isSet bool
}

func (v NullablePreviewType) Get() *PreviewType {
	return v.value
}

func (v *NullablePreviewType) Set(val *PreviewType) {
	v.value = val
	v.isSet = true
}

func (v NullablePreviewType) IsSet() bool {
	return v.isSet
}

func (v *NullablePreviewType) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullablePreviewType(val *PreviewType) *NullablePreviewType {
	return &NullablePreviewType{value: val, isSet: true}
}

func (v NullablePreviewType) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullablePreviewType) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
