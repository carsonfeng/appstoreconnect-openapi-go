/*
App Store Connect API

No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)

API version: 2.3
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package openapi

import (
	"encoding/json"
)

// checks if the ReviewSubmissionItemUpdateRequest type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &ReviewSubmissionItemUpdateRequest{}

// ReviewSubmissionItemUpdateRequest struct for ReviewSubmissionItemUpdateRequest
type ReviewSubmissionItemUpdateRequest struct {
	Data ReviewSubmissionItemUpdateRequestData `json:"data"`
}

// NewReviewSubmissionItemUpdateRequest instantiates a new ReviewSubmissionItemUpdateRequest object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewReviewSubmissionItemUpdateRequest(data ReviewSubmissionItemUpdateRequestData) *ReviewSubmissionItemUpdateRequest {
	this := ReviewSubmissionItemUpdateRequest{}
	this.Data = data
	return &this
}

// NewReviewSubmissionItemUpdateRequestWithDefaults instantiates a new ReviewSubmissionItemUpdateRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewReviewSubmissionItemUpdateRequestWithDefaults() *ReviewSubmissionItemUpdateRequest {
	this := ReviewSubmissionItemUpdateRequest{}
	return &this
}

// GetData returns the Data field value
func (o *ReviewSubmissionItemUpdateRequest) GetData() ReviewSubmissionItemUpdateRequestData {
	if o == nil {
		var ret ReviewSubmissionItemUpdateRequestData
		return ret
	}

	return o.Data
}

// GetDataOk returns a tuple with the Data field value
// and a boolean to check if the value has been set.
func (o *ReviewSubmissionItemUpdateRequest) GetDataOk() (*ReviewSubmissionItemUpdateRequestData, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Data, true
}

// SetData sets field value
func (o *ReviewSubmissionItemUpdateRequest) SetData(v ReviewSubmissionItemUpdateRequestData) {
	o.Data = v
}

func (o ReviewSubmissionItemUpdateRequest) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o ReviewSubmissionItemUpdateRequest) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["data"] = o.Data
	return toSerialize, nil
}

type NullableReviewSubmissionItemUpdateRequest struct {
	value *ReviewSubmissionItemUpdateRequest
	isSet bool
}

func (v NullableReviewSubmissionItemUpdateRequest) Get() *ReviewSubmissionItemUpdateRequest {
	return v.value
}

func (v *NullableReviewSubmissionItemUpdateRequest) Set(val *ReviewSubmissionItemUpdateRequest) {
	v.value = val
	v.isSet = true
}

func (v NullableReviewSubmissionItemUpdateRequest) IsSet() bool {
	return v.isSet
}

func (v *NullableReviewSubmissionItemUpdateRequest) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableReviewSubmissionItemUpdateRequest(val *ReviewSubmissionItemUpdateRequest) *NullableReviewSubmissionItemUpdateRequest {
	return &NullableReviewSubmissionItemUpdateRequest{value: val, isSet: true}
}

func (v NullableReviewSubmissionItemUpdateRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableReviewSubmissionItemUpdateRequest) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
