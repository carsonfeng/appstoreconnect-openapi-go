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

// ReviewSubmissionsResponseIncludedInner - struct for ReviewSubmissionsResponseIncludedInner
type ReviewSubmissionsResponseIncludedInner struct {
	App                  *App
	AppStoreVersion      *AppStoreVersion
	ReviewSubmissionItem *ReviewSubmissionItem
}

// AppAsReviewSubmissionsResponseIncludedInner is a convenience function that returns App wrapped in ReviewSubmissionsResponseIncludedInner
func AppAsReviewSubmissionsResponseIncludedInner(v *App) ReviewSubmissionsResponseIncludedInner {
	return ReviewSubmissionsResponseIncludedInner{
		App: v,
	}
}

// AppStoreVersionAsReviewSubmissionsResponseIncludedInner is a convenience function that returns AppStoreVersion wrapped in ReviewSubmissionsResponseIncludedInner
func AppStoreVersionAsReviewSubmissionsResponseIncludedInner(v *AppStoreVersion) ReviewSubmissionsResponseIncludedInner {
	return ReviewSubmissionsResponseIncludedInner{
		AppStoreVersion: v,
	}
}

// ReviewSubmissionItemAsReviewSubmissionsResponseIncludedInner is a convenience function that returns ReviewSubmissionItem wrapped in ReviewSubmissionsResponseIncludedInner
func ReviewSubmissionItemAsReviewSubmissionsResponseIncludedInner(v *ReviewSubmissionItem) ReviewSubmissionsResponseIncludedInner {
	return ReviewSubmissionsResponseIncludedInner{
		ReviewSubmissionItem: v,
	}
}

// Unmarshal JSON data into one of the pointers in the struct
func (dst *ReviewSubmissionsResponseIncludedInner) UnmarshalJSON(data []byte) error {
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

	// try to unmarshal data into AppStoreVersion
	err = newStrictDecoder(data).Decode(&dst.AppStoreVersion)
	if err == nil {
		jsonAppStoreVersion, _ := json.Marshal(dst.AppStoreVersion)
		if string(jsonAppStoreVersion) == "{}" { // empty struct
			dst.AppStoreVersion = nil
		} else {
			match++
		}
	} else {
		dst.AppStoreVersion = nil
	}

	// try to unmarshal data into ReviewSubmissionItem
	err = newStrictDecoder(data).Decode(&dst.ReviewSubmissionItem)
	if err == nil {
		jsonReviewSubmissionItem, _ := json.Marshal(dst.ReviewSubmissionItem)
		if string(jsonReviewSubmissionItem) == "{}" { // empty struct
			dst.ReviewSubmissionItem = nil
		} else {
			match++
		}
	} else {
		dst.ReviewSubmissionItem = nil
	}

	if match > 1 { // more than 1 match
		// reset to nil
		dst.App = nil
		dst.AppStoreVersion = nil
		dst.ReviewSubmissionItem = nil

		return fmt.Errorf("data matches more than one schema in oneOf(ReviewSubmissionsResponseIncludedInner)")
	} else if match == 1 {
		return nil // exactly one match
	} else { // no match
		return fmt.Errorf("data failed to match schemas in oneOf(ReviewSubmissionsResponseIncludedInner)")
	}
}

// Marshal data from the first non-nil pointers in the struct to JSON
func (src ReviewSubmissionsResponseIncludedInner) MarshalJSON() ([]byte, error) {
	if src.App != nil {
		return json.Marshal(&src.App)
	}

	if src.AppStoreVersion != nil {
		return json.Marshal(&src.AppStoreVersion)
	}

	if src.ReviewSubmissionItem != nil {
		return json.Marshal(&src.ReviewSubmissionItem)
	}

	return nil, nil // no data in oneOf schemas
}

// Get the actual instance
func (obj *ReviewSubmissionsResponseIncludedInner) GetActualInstance() interface{} {
	if obj == nil {
		return nil
	}
	if obj.App != nil {
		return obj.App
	}

	if obj.AppStoreVersion != nil {
		return obj.AppStoreVersion
	}

	if obj.ReviewSubmissionItem != nil {
		return obj.ReviewSubmissionItem
	}

	// all schemas are nil
	return nil
}

type NullableReviewSubmissionsResponseIncludedInner struct {
	value *ReviewSubmissionsResponseIncludedInner
	isSet bool
}

func (v NullableReviewSubmissionsResponseIncludedInner) Get() *ReviewSubmissionsResponseIncludedInner {
	return v.value
}

func (v *NullableReviewSubmissionsResponseIncludedInner) Set(val *ReviewSubmissionsResponseIncludedInner) {
	v.value = val
	v.isSet = true
}

func (v NullableReviewSubmissionsResponseIncludedInner) IsSet() bool {
	return v.isSet
}

func (v *NullableReviewSubmissionsResponseIncludedInner) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableReviewSubmissionsResponseIncludedInner(val *ReviewSubmissionsResponseIncludedInner) *NullableReviewSubmissionsResponseIncludedInner {
	return &NullableReviewSubmissionsResponseIncludedInner{value: val, isSet: true}
}

func (v NullableReviewSubmissionsResponseIncludedInner) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableReviewSubmissionsResponseIncludedInner) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
