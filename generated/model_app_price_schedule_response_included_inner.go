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

// AppPriceScheduleResponseIncludedInner - struct for AppPriceScheduleResponseIncludedInner
type AppPriceScheduleResponseIncludedInner struct {
	App        *App
	AppPriceV2 *AppPriceV2
	Territory  *Territory
}

// AppAsAppPriceScheduleResponseIncludedInner is a convenience function that returns App wrapped in AppPriceScheduleResponseIncludedInner
func AppAsAppPriceScheduleResponseIncludedInner(v *App) AppPriceScheduleResponseIncludedInner {
	return AppPriceScheduleResponseIncludedInner{
		App: v,
	}
}

// AppPriceV2AsAppPriceScheduleResponseIncludedInner is a convenience function that returns AppPriceV2 wrapped in AppPriceScheduleResponseIncludedInner
func AppPriceV2AsAppPriceScheduleResponseIncludedInner(v *AppPriceV2) AppPriceScheduleResponseIncludedInner {
	return AppPriceScheduleResponseIncludedInner{
		AppPriceV2: v,
	}
}

// TerritoryAsAppPriceScheduleResponseIncludedInner is a convenience function that returns Territory wrapped in AppPriceScheduleResponseIncludedInner
func TerritoryAsAppPriceScheduleResponseIncludedInner(v *Territory) AppPriceScheduleResponseIncludedInner {
	return AppPriceScheduleResponseIncludedInner{
		Territory: v,
	}
}

// Unmarshal JSON data into one of the pointers in the struct
func (dst *AppPriceScheduleResponseIncludedInner) UnmarshalJSON(data []byte) error {
	var err error
	match := 0
	// try to unmarshal data into App
	err = newStrictDecoder(data).Decode(&dst.App)
	if err == nil {
		jsonApp, _ := json.Marshal(dst.App)
		if string(jsonApp) == "{}" { // empty struct
			dst.App = nil
		} else {
			match++
		}
	} else {
		dst.App = nil
	}

	// try to unmarshal data into AppPriceV2
	err = newStrictDecoder(data).Decode(&dst.AppPriceV2)
	if err == nil {
		jsonAppPriceV2, _ := json.Marshal(dst.AppPriceV2)
		if string(jsonAppPriceV2) == "{}" { // empty struct
			dst.AppPriceV2 = nil
		} else {
			match++
		}
	} else {
		dst.AppPriceV2 = nil
	}

	// try to unmarshal data into Territory
	err = newStrictDecoder(data).Decode(&dst.Territory)
	if err == nil {
		jsonTerritory, _ := json.Marshal(dst.Territory)
		if string(jsonTerritory) == "{}" { // empty struct
			dst.Territory = nil
		} else {
			match++
		}
	} else {
		dst.Territory = nil
	}

	if match > 1 { // more than 1 match
		// reset to nil
		dst.App = nil
		dst.AppPriceV2 = nil
		dst.Territory = nil

		return fmt.Errorf("data matches more than one schema in oneOf(AppPriceScheduleResponseIncludedInner)")
	} else if match == 1 {
		return nil // exactly one match
	} else { // no match
		return fmt.Errorf("data failed to match schemas in oneOf(AppPriceScheduleResponseIncludedInner)")
	}
}

// Marshal data from the first non-nil pointers in the struct to JSON
func (src AppPriceScheduleResponseIncludedInner) MarshalJSON() ([]byte, error) {
	if src.App != nil {
		return json.Marshal(&src.App)
	}

	if src.AppPriceV2 != nil {
		return json.Marshal(&src.AppPriceV2)
	}

	if src.Territory != nil {
		return json.Marshal(&src.Territory)
	}

	return nil, nil // no data in oneOf schemas
}

// Get the actual instance
func (obj *AppPriceScheduleResponseIncludedInner) GetActualInstance() interface{} {
	if obj == nil {
		return nil
	}
	if obj.App != nil {
		return obj.App
	}

	if obj.AppPriceV2 != nil {
		return obj.AppPriceV2
	}

	if obj.Territory != nil {
		return obj.Territory
	}

	// all schemas are nil
	return nil
}

type NullableAppPriceScheduleResponseIncludedInner struct {
	value *AppPriceScheduleResponseIncludedInner
	isSet bool
}

func (v NullableAppPriceScheduleResponseIncludedInner) Get() *AppPriceScheduleResponseIncludedInner {
	return v.value
}

func (v *NullableAppPriceScheduleResponseIncludedInner) Set(val *AppPriceScheduleResponseIncludedInner) {
	v.value = val
	v.isSet = true
}

func (v NullableAppPriceScheduleResponseIncludedInner) IsSet() bool {
	return v.isSet
}

func (v *NullableAppPriceScheduleResponseIncludedInner) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableAppPriceScheduleResponseIncludedInner(val *AppPriceScheduleResponseIncludedInner) *NullableAppPriceScheduleResponseIncludedInner {
	return &NullableAppPriceScheduleResponseIncludedInner{value: val, isSet: true}
}

func (v NullableAppPriceScheduleResponseIncludedInner) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableAppPriceScheduleResponseIncludedInner) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
