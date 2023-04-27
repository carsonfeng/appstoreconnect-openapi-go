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

// checks if the ReviewSubmissionItemCreateRequestDataRelationshipsReviewSubmission type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &ReviewSubmissionItemCreateRequestDataRelationshipsReviewSubmission{}

// ReviewSubmissionItemCreateRequestDataRelationshipsReviewSubmission struct for ReviewSubmissionItemCreateRequestDataRelationshipsReviewSubmission
type ReviewSubmissionItemCreateRequestDataRelationshipsReviewSubmission struct {
	Data AppRelationshipsReviewSubmissionsDataInner `json:"data"`
}

// NewReviewSubmissionItemCreateRequestDataRelationshipsReviewSubmission instantiates a new ReviewSubmissionItemCreateRequestDataRelationshipsReviewSubmission object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewReviewSubmissionItemCreateRequestDataRelationshipsReviewSubmission(data AppRelationshipsReviewSubmissionsDataInner) *ReviewSubmissionItemCreateRequestDataRelationshipsReviewSubmission {
	this := ReviewSubmissionItemCreateRequestDataRelationshipsReviewSubmission{}
	this.Data = data
	return &this
}

// NewReviewSubmissionItemCreateRequestDataRelationshipsReviewSubmissionWithDefaults instantiates a new ReviewSubmissionItemCreateRequestDataRelationshipsReviewSubmission object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewReviewSubmissionItemCreateRequestDataRelationshipsReviewSubmissionWithDefaults() *ReviewSubmissionItemCreateRequestDataRelationshipsReviewSubmission {
	this := ReviewSubmissionItemCreateRequestDataRelationshipsReviewSubmission{}
	return &this
}

// GetData returns the Data field value
func (o *ReviewSubmissionItemCreateRequestDataRelationshipsReviewSubmission) GetData() AppRelationshipsReviewSubmissionsDataInner {
	if o == nil {
		var ret AppRelationshipsReviewSubmissionsDataInner
		return ret
	}

	return o.Data
}

// GetDataOk returns a tuple with the Data field value
// and a boolean to check if the value has been set.
func (o *ReviewSubmissionItemCreateRequestDataRelationshipsReviewSubmission) GetDataOk() (*AppRelationshipsReviewSubmissionsDataInner, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Data, true
}

// SetData sets field value
func (o *ReviewSubmissionItemCreateRequestDataRelationshipsReviewSubmission) SetData(v AppRelationshipsReviewSubmissionsDataInner) {
	o.Data = v
}

func (o ReviewSubmissionItemCreateRequestDataRelationshipsReviewSubmission) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o ReviewSubmissionItemCreateRequestDataRelationshipsReviewSubmission) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["data"] = o.Data
	return toSerialize, nil
}

type NullableReviewSubmissionItemCreateRequestDataRelationshipsReviewSubmission struct {
	value *ReviewSubmissionItemCreateRequestDataRelationshipsReviewSubmission
	isSet bool
}

func (v NullableReviewSubmissionItemCreateRequestDataRelationshipsReviewSubmission) Get() *ReviewSubmissionItemCreateRequestDataRelationshipsReviewSubmission {
	return v.value
}

func (v *NullableReviewSubmissionItemCreateRequestDataRelationshipsReviewSubmission) Set(val *ReviewSubmissionItemCreateRequestDataRelationshipsReviewSubmission) {
	v.value = val
	v.isSet = true
}

func (v NullableReviewSubmissionItemCreateRequestDataRelationshipsReviewSubmission) IsSet() bool {
	return v.isSet
}

func (v *NullableReviewSubmissionItemCreateRequestDataRelationshipsReviewSubmission) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableReviewSubmissionItemCreateRequestDataRelationshipsReviewSubmission(val *ReviewSubmissionItemCreateRequestDataRelationshipsReviewSubmission) *NullableReviewSubmissionItemCreateRequestDataRelationshipsReviewSubmission {
	return &NullableReviewSubmissionItemCreateRequestDataRelationshipsReviewSubmission{value: val, isSet: true}
}

func (v NullableReviewSubmissionItemCreateRequestDataRelationshipsReviewSubmission) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableReviewSubmissionItemCreateRequestDataRelationshipsReviewSubmission) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
