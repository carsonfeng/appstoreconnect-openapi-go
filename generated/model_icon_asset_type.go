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

// IconAssetType the model 'IconAssetType'
type IconAssetType string

// List of IconAssetType
const (
	APP_STORE            IconAssetType = "APP_STORE"
	MESSAGES_APP_STORE   IconAssetType = "MESSAGES_APP_STORE"
	WATCH_APP_STORE      IconAssetType = "WATCH_APP_STORE"
	TV_OS_HOME_SCREEN    IconAssetType = "TV_OS_HOME_SCREEN"
	TV_OS_TOP_SHELF      IconAssetType = "TV_OS_TOP_SHELF"
	ALTERNATE_EXPERIMENT IconAssetType = "ALTERNATE_EXPERIMENT"
)

// All allowed values of IconAssetType enum
var AllowedIconAssetTypeEnumValues = []IconAssetType{
	"APP_STORE",
	"MESSAGES_APP_STORE",
	"WATCH_APP_STORE",
	"TV_OS_HOME_SCREEN",
	"TV_OS_TOP_SHELF",
	"ALTERNATE_EXPERIMENT",
}

func (v *IconAssetType) UnmarshalJSON(src []byte) error {
	var value string
	err := json.Unmarshal(src, &value)
	if err != nil {
		return err
	}
	enumTypeValue := IconAssetType(value)
	for _, existing := range AllowedIconAssetTypeEnumValues {
		if existing == enumTypeValue {
			*v = enumTypeValue
			return nil
		}
	}

	return fmt.Errorf("%+v is not a valid IconAssetType", value)
}

// NewIconAssetTypeFromValue returns a pointer to a valid IconAssetType
// for the value passed as argument, or an error if the value passed is not allowed by the enum
func NewIconAssetTypeFromValue(v string) (*IconAssetType, error) {
	ev := IconAssetType(v)
	if ev.IsValid() {
		return &ev, nil
	} else {
		return nil, fmt.Errorf("invalid value '%v' for IconAssetType: valid values are %v", v, AllowedIconAssetTypeEnumValues)
	}
}

// IsValid return true if the value is valid for the enum, false otherwise
func (v IconAssetType) IsValid() bool {
	for _, existing := range AllowedIconAssetTypeEnumValues {
		if existing == v {
			return true
		}
	}
	return false
}

// Ptr returns reference to IconAssetType value
func (v IconAssetType) Ptr() *IconAssetType {
	return &v
}

type NullableIconAssetType struct {
	value *IconAssetType
	isSet bool
}

func (v NullableIconAssetType) Get() *IconAssetType {
	return v.value
}

func (v *NullableIconAssetType) Set(val *IconAssetType) {
	v.value = val
	v.isSet = true
}

func (v NullableIconAssetType) IsSet() bool {
	return v.isSet
}

func (v *NullableIconAssetType) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableIconAssetType(val *IconAssetType) *NullableIconAssetType {
	return &NullableIconAssetType{value: val, isSet: true}
}

func (v NullableIconAssetType) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableIconAssetType) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
