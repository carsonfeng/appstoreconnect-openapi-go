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

// AppPricesV2ResponseIncludedInner - struct for AppPricesV2ResponseIncludedInner
type AppPricesV2ResponseIncludedInner struct {
	AppPricePointV3 *AppPricePointV3
	Territory       *Territory
}

// AppPricePointV3AsAppPricesV2ResponseIncludedInner is a convenience function that returns AppPricePointV3 wrapped in AppPricesV2ResponseIncludedInner
func AppPricePointV3AsAppPricesV2ResponseIncludedInner(v *AppPricePointV3) AppPricesV2ResponseIncludedInner {
	return AppPricesV2ResponseIncludedInner{
		AppPricePointV3: v,
	}
}

// TerritoryAsAppPricesV2ResponseIncludedInner is a convenience function that returns Territory wrapped in AppPricesV2ResponseIncludedInner
func TerritoryAsAppPricesV2ResponseIncludedInner(v *Territory) AppPricesV2ResponseIncludedInner {
	return AppPricesV2ResponseIncludedInner{
		Territory: v,
	}
}

// Unmarshal JSON data into one of the pointers in the struct
func (dst *AppPricesV2ResponseIncludedInner) UnmarshalJSON(data []byte) error {
	var err error
	match := 0
	// try to unmarshal data into AppPricePointV3
	err = newStrictDecoder(data).Decode(&dst.AppPricePointV3)
	if err == nil {
		jsonAppPricePointV3, _ := json.Marshal(dst.AppPricePointV3)
		if string(jsonAppPricePointV3) == "{}" { // empty struct
			dst.AppPricePointV3 = nil
		} else {
			match++
		}
	} else {
		dst.AppPricePointV3 = nil
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
		dst.AppPricePointV3 = nil
		dst.Territory = nil

		return fmt.Errorf("data matches more than one schema in oneOf(AppPricesV2ResponseIncludedInner)")
	} else if match == 1 {
		return nil // exactly one match
	} else { // no match
		return fmt.Errorf("data failed to match schemas in oneOf(AppPricesV2ResponseIncludedInner)")
	}
}

// Marshal data from the first non-nil pointers in the struct to JSON
func (src AppPricesV2ResponseIncludedInner) MarshalJSON() ([]byte, error) {
	if src.AppPricePointV3 != nil {
		return json.Marshal(&src.AppPricePointV3)
	}

	if src.Territory != nil {
		return json.Marshal(&src.Territory)
	}

	return nil, nil // no data in oneOf schemas
}

// Get the actual instance
func (obj *AppPricesV2ResponseIncludedInner) GetActualInstance() interface{} {
	if obj == nil {
		return nil
	}
	if obj.AppPricePointV3 != nil {
		return obj.AppPricePointV3
	}

	if obj.Territory != nil {
		return obj.Territory
	}

	// all schemas are nil
	return nil
}

type NullableAppPricesV2ResponseIncludedInner struct {
	value *AppPricesV2ResponseIncludedInner
	isSet bool
}

func (v NullableAppPricesV2ResponseIncludedInner) Get() *AppPricesV2ResponseIncludedInner {
	return v.value
}

func (v *NullableAppPricesV2ResponseIncludedInner) Set(val *AppPricesV2ResponseIncludedInner) {
	v.value = val
	v.isSet = true
}

func (v NullableAppPricesV2ResponseIncludedInner) IsSet() bool {
	return v.isSet
}

func (v *NullableAppPricesV2ResponseIncludedInner) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableAppPricesV2ResponseIncludedInner(val *AppPricesV2ResponseIncludedInner) *NullableAppPricesV2ResponseIncludedInner {
	return &NullableAppPricesV2ResponseIncludedInner{value: val, isSet: true}
}

func (v NullableAppPricesV2ResponseIncludedInner) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableAppPricesV2ResponseIncludedInner) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
