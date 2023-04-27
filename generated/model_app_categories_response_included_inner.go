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

// AppCategoriesResponseIncludedInner - struct for AppCategoriesResponseIncludedInner
type AppCategoriesResponseIncludedInner struct {
	AppCategory *AppCategory
}

// AppCategoryAsAppCategoriesResponseIncludedInner is a convenience function that returns AppCategory wrapped in AppCategoriesResponseIncludedInner
func AppCategoryAsAppCategoriesResponseIncludedInner(v *AppCategory) AppCategoriesResponseIncludedInner {
	return AppCategoriesResponseIncludedInner{
		AppCategory: v,
	}
}

// Unmarshal JSON data into one of the pointers in the struct
func (dst *AppCategoriesResponseIncludedInner) UnmarshalJSON(data []byte) error {
	var err error
	match := 0
	// try to unmarshal data into AppCategory
	err = newStrictDecoder(data).Decode(&dst.AppCategory)
	if err == nil {
		jsonAppCategory, _ := json.Marshal(dst.AppCategory)
		if string(jsonAppCategory) == "{}" { // empty struct
			dst.AppCategory = nil
		} else {
			match++
		}
	} else {
		dst.AppCategory = nil
	}

	if match > 1 { // more than 1 match
		// reset to nil
		dst.AppCategory = nil

		return fmt.Errorf("data matches more than one schema in oneOf(AppCategoriesResponseIncludedInner)")
	} else if match == 1 {
		return nil // exactly one match
	} else { // no match
		return fmt.Errorf("data failed to match schemas in oneOf(AppCategoriesResponseIncludedInner)")
	}
}

// Marshal data from the first non-nil pointers in the struct to JSON
func (src AppCategoriesResponseIncludedInner) MarshalJSON() ([]byte, error) {
	if src.AppCategory != nil {
		return json.Marshal(&src.AppCategory)
	}

	return nil, nil // no data in oneOf schemas
}

// Get the actual instance
func (obj *AppCategoriesResponseIncludedInner) GetActualInstance() interface{} {
	if obj == nil {
		return nil
	}
	if obj.AppCategory != nil {
		return obj.AppCategory
	}

	// all schemas are nil
	return nil
}

type NullableAppCategoriesResponseIncludedInner struct {
	value *AppCategoriesResponseIncludedInner
	isSet bool
}

func (v NullableAppCategoriesResponseIncludedInner) Get() *AppCategoriesResponseIncludedInner {
	return v.value
}

func (v *NullableAppCategoriesResponseIncludedInner) Set(val *AppCategoriesResponseIncludedInner) {
	v.value = val
	v.isSet = true
}

func (v NullableAppCategoriesResponseIncludedInner) IsSet() bool {
	return v.isSet
}

func (v *NullableAppCategoriesResponseIncludedInner) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableAppCategoriesResponseIncludedInner(val *AppCategoriesResponseIncludedInner) *NullableAppCategoriesResponseIncludedInner {
	return &NullableAppCategoriesResponseIncludedInner{value: val, isSet: true}
}

func (v NullableAppCategoriesResponseIncludedInner) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableAppCategoriesResponseIncludedInner) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}