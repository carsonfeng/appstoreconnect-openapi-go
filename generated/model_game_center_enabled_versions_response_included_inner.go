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

// GameCenterEnabledVersionsResponseIncludedInner - struct for GameCenterEnabledVersionsResponseIncludedInner
type GameCenterEnabledVersionsResponseIncludedInner struct {
	App                      *App
	GameCenterEnabledVersion *GameCenterEnabledVersion
}

// AppAsGameCenterEnabledVersionsResponseIncludedInner is a convenience function that returns App wrapped in GameCenterEnabledVersionsResponseIncludedInner
func AppAsGameCenterEnabledVersionsResponseIncludedInner(v *App) GameCenterEnabledVersionsResponseIncludedInner {
	return GameCenterEnabledVersionsResponseIncludedInner{
		App: v,
	}
}

// GameCenterEnabledVersionAsGameCenterEnabledVersionsResponseIncludedInner is a convenience function that returns GameCenterEnabledVersion wrapped in GameCenterEnabledVersionsResponseIncludedInner
func GameCenterEnabledVersionAsGameCenterEnabledVersionsResponseIncludedInner(v *GameCenterEnabledVersion) GameCenterEnabledVersionsResponseIncludedInner {
	return GameCenterEnabledVersionsResponseIncludedInner{
		GameCenterEnabledVersion: v,
	}
}

// Unmarshal JSON data into one of the pointers in the struct
func (dst *GameCenterEnabledVersionsResponseIncludedInner) UnmarshalJSON(data []byte) error {
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

	// try to unmarshal data into GameCenterEnabledVersion
	err = newStrictDecoder(data).Decode(&dst.GameCenterEnabledVersion)
	if err == nil {
		jsonGameCenterEnabledVersion, _ := json.Marshal(dst.GameCenterEnabledVersion)
		if string(jsonGameCenterEnabledVersion) == "{}" { // empty struct
			dst.GameCenterEnabledVersion = nil
		} else {
			match++
		}
	} else {
		dst.GameCenterEnabledVersion = nil
	}

	if match > 1 { // more than 1 match
		// reset to nil
		dst.App = nil
		dst.GameCenterEnabledVersion = nil

		return fmt.Errorf("data matches more than one schema in oneOf(GameCenterEnabledVersionsResponseIncludedInner)")
	} else if match == 1 {
		return nil // exactly one match
	} else { // no match
		return fmt.Errorf("data failed to match schemas in oneOf(GameCenterEnabledVersionsResponseIncludedInner)")
	}
}

// Marshal data from the first non-nil pointers in the struct to JSON
func (src GameCenterEnabledVersionsResponseIncludedInner) MarshalJSON() ([]byte, error) {
	if src.App != nil {
		return json.Marshal(&src.App)
	}

	if src.GameCenterEnabledVersion != nil {
		return json.Marshal(&src.GameCenterEnabledVersion)
	}

	return nil, nil // no data in oneOf schemas
}

// Get the actual instance
func (obj *GameCenterEnabledVersionsResponseIncludedInner) GetActualInstance() interface{} {
	if obj == nil {
		return nil
	}
	if obj.App != nil {
		return obj.App
	}

	if obj.GameCenterEnabledVersion != nil {
		return obj.GameCenterEnabledVersion
	}

	// all schemas are nil
	return nil
}

type NullableGameCenterEnabledVersionsResponseIncludedInner struct {
	value *GameCenterEnabledVersionsResponseIncludedInner
	isSet bool
}

func (v NullableGameCenterEnabledVersionsResponseIncludedInner) Get() *GameCenterEnabledVersionsResponseIncludedInner {
	return v.value
}

func (v *NullableGameCenterEnabledVersionsResponseIncludedInner) Set(val *GameCenterEnabledVersionsResponseIncludedInner) {
	v.value = val
	v.isSet = true
}

func (v NullableGameCenterEnabledVersionsResponseIncludedInner) IsSet() bool {
	return v.isSet
}

func (v *NullableGameCenterEnabledVersionsResponseIncludedInner) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableGameCenterEnabledVersionsResponseIncludedInner(val *GameCenterEnabledVersionsResponseIncludedInner) *NullableGameCenterEnabledVersionsResponseIncludedInner {
	return &NullableGameCenterEnabledVersionsResponseIncludedInner{value: val, isSet: true}
}

func (v NullableGameCenterEnabledVersionsResponseIncludedInner) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableGameCenterEnabledVersionsResponseIncludedInner) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
