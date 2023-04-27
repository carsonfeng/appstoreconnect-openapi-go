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

// AppCustomProductPageLocalizationsResponseIncludedInner - struct for AppCustomProductPageLocalizationsResponseIncludedInner
type AppCustomProductPageLocalizationsResponseIncludedInner struct {
	AppCustomProductPageVersion *AppCustomProductPageVersion
	AppPreviewSet               *AppPreviewSet
	AppScreenshotSet            *AppScreenshotSet
}

// AppCustomProductPageVersionAsAppCustomProductPageLocalizationsResponseIncludedInner is a convenience function that returns AppCustomProductPageVersion wrapped in AppCustomProductPageLocalizationsResponseIncludedInner
func AppCustomProductPageVersionAsAppCustomProductPageLocalizationsResponseIncludedInner(v *AppCustomProductPageVersion) AppCustomProductPageLocalizationsResponseIncludedInner {
	return AppCustomProductPageLocalizationsResponseIncludedInner{
		AppCustomProductPageVersion: v,
	}
}

// AppPreviewSetAsAppCustomProductPageLocalizationsResponseIncludedInner is a convenience function that returns AppPreviewSet wrapped in AppCustomProductPageLocalizationsResponseIncludedInner
func AppPreviewSetAsAppCustomProductPageLocalizationsResponseIncludedInner(v *AppPreviewSet) AppCustomProductPageLocalizationsResponseIncludedInner {
	return AppCustomProductPageLocalizationsResponseIncludedInner{
		AppPreviewSet: v,
	}
}

// AppScreenshotSetAsAppCustomProductPageLocalizationsResponseIncludedInner is a convenience function that returns AppScreenshotSet wrapped in AppCustomProductPageLocalizationsResponseIncludedInner
func AppScreenshotSetAsAppCustomProductPageLocalizationsResponseIncludedInner(v *AppScreenshotSet) AppCustomProductPageLocalizationsResponseIncludedInner {
	return AppCustomProductPageLocalizationsResponseIncludedInner{
		AppScreenshotSet: v,
	}
}

// Unmarshal JSON data into one of the pointers in the struct
func (dst *AppCustomProductPageLocalizationsResponseIncludedInner) UnmarshalJSON(data []byte) error {
	var err error
	match := 0
	// try to unmarshal data into AppCustomProductPageVersion
	err = newStrictDecoder(data).Decode(&dst.AppCustomProductPageVersion)
	if err == nil {
		jsonAppCustomProductPageVersion, _ := json.Marshal(dst.AppCustomProductPageVersion)
		if string(jsonAppCustomProductPageVersion) == "{}" { // empty struct
			dst.AppCustomProductPageVersion = nil
		} else {
			match++
		}
	} else {
		dst.AppCustomProductPageVersion = nil
	}

	// try to unmarshal data into AppPreviewSet
	err = newStrictDecoder(data).Decode(&dst.AppPreviewSet)
	if err == nil {
		jsonAppPreviewSet, _ := json.Marshal(dst.AppPreviewSet)
		if string(jsonAppPreviewSet) == "{}" { // empty struct
			dst.AppPreviewSet = nil
		} else {
			match++
		}
	} else {
		dst.AppPreviewSet = nil
	}

	// try to unmarshal data into AppScreenshotSet
	err = newStrictDecoder(data).Decode(&dst.AppScreenshotSet)
	if err == nil {
		jsonAppScreenshotSet, _ := json.Marshal(dst.AppScreenshotSet)
		if string(jsonAppScreenshotSet) == "{}" { // empty struct
			dst.AppScreenshotSet = nil
		} else {
			match++
		}
	} else {
		dst.AppScreenshotSet = nil
	}

	if match > 1 { // more than 1 match
		// reset to nil
		dst.AppCustomProductPageVersion = nil
		dst.AppPreviewSet = nil
		dst.AppScreenshotSet = nil

		return fmt.Errorf("data matches more than one schema in oneOf(AppCustomProductPageLocalizationsResponseIncludedInner)")
	} else if match == 1 {
		return nil // exactly one match
	} else { // no match
		return fmt.Errorf("data failed to match schemas in oneOf(AppCustomProductPageLocalizationsResponseIncludedInner)")
	}
}

// Marshal data from the first non-nil pointers in the struct to JSON
func (src AppCustomProductPageLocalizationsResponseIncludedInner) MarshalJSON() ([]byte, error) {
	if src.AppCustomProductPageVersion != nil {
		return json.Marshal(&src.AppCustomProductPageVersion)
	}

	if src.AppPreviewSet != nil {
		return json.Marshal(&src.AppPreviewSet)
	}

	if src.AppScreenshotSet != nil {
		return json.Marshal(&src.AppScreenshotSet)
	}

	return nil, nil // no data in oneOf schemas
}

// Get the actual instance
func (obj *AppCustomProductPageLocalizationsResponseIncludedInner) GetActualInstance() interface{} {
	if obj == nil {
		return nil
	}
	if obj.AppCustomProductPageVersion != nil {
		return obj.AppCustomProductPageVersion
	}

	if obj.AppPreviewSet != nil {
		return obj.AppPreviewSet
	}

	if obj.AppScreenshotSet != nil {
		return obj.AppScreenshotSet
	}

	// all schemas are nil
	return nil
}

type NullableAppCustomProductPageLocalizationsResponseIncludedInner struct {
	value *AppCustomProductPageLocalizationsResponseIncludedInner
	isSet bool
}

func (v NullableAppCustomProductPageLocalizationsResponseIncludedInner) Get() *AppCustomProductPageLocalizationsResponseIncludedInner {
	return v.value
}

func (v *NullableAppCustomProductPageLocalizationsResponseIncludedInner) Set(val *AppCustomProductPageLocalizationsResponseIncludedInner) {
	v.value = val
	v.isSet = true
}

func (v NullableAppCustomProductPageLocalizationsResponseIncludedInner) IsSet() bool {
	return v.isSet
}

func (v *NullableAppCustomProductPageLocalizationsResponseIncludedInner) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableAppCustomProductPageLocalizationsResponseIncludedInner(val *AppCustomProductPageLocalizationsResponseIncludedInner) *NullableAppCustomProductPageLocalizationsResponseIncludedInner {
	return &NullableAppCustomProductPageLocalizationsResponseIncludedInner{value: val, isSet: true}
}

func (v NullableAppCustomProductPageLocalizationsResponseIncludedInner) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableAppCustomProductPageLocalizationsResponseIncludedInner) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}