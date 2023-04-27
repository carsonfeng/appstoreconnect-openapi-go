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

// checks if the ReviewSubmissionItemCreateRequestDataRelationshipsAppStoreVersionExperiment type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &ReviewSubmissionItemCreateRequestDataRelationshipsAppStoreVersionExperiment{}

// ReviewSubmissionItemCreateRequestDataRelationshipsAppStoreVersionExperiment struct for ReviewSubmissionItemCreateRequestDataRelationshipsAppStoreVersionExperiment
type ReviewSubmissionItemCreateRequestDataRelationshipsAppStoreVersionExperiment struct {
	Data *AppStoreVersionExperimentTreatmentRelationshipsAppStoreVersionExperimentData `json:"data,omitempty"`
}

// NewReviewSubmissionItemCreateRequestDataRelationshipsAppStoreVersionExperiment instantiates a new ReviewSubmissionItemCreateRequestDataRelationshipsAppStoreVersionExperiment object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewReviewSubmissionItemCreateRequestDataRelationshipsAppStoreVersionExperiment() *ReviewSubmissionItemCreateRequestDataRelationshipsAppStoreVersionExperiment {
	this := ReviewSubmissionItemCreateRequestDataRelationshipsAppStoreVersionExperiment{}
	return &this
}

// NewReviewSubmissionItemCreateRequestDataRelationshipsAppStoreVersionExperimentWithDefaults instantiates a new ReviewSubmissionItemCreateRequestDataRelationshipsAppStoreVersionExperiment object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewReviewSubmissionItemCreateRequestDataRelationshipsAppStoreVersionExperimentWithDefaults() *ReviewSubmissionItemCreateRequestDataRelationshipsAppStoreVersionExperiment {
	this := ReviewSubmissionItemCreateRequestDataRelationshipsAppStoreVersionExperiment{}
	return &this
}

// GetData returns the Data field value if set, zero value otherwise.
func (o *ReviewSubmissionItemCreateRequestDataRelationshipsAppStoreVersionExperiment) GetData() AppStoreVersionExperimentTreatmentRelationshipsAppStoreVersionExperimentData {
	if o == nil || IsNil(o.Data) {
		var ret AppStoreVersionExperimentTreatmentRelationshipsAppStoreVersionExperimentData
		return ret
	}
	return *o.Data
}

// GetDataOk returns a tuple with the Data field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ReviewSubmissionItemCreateRequestDataRelationshipsAppStoreVersionExperiment) GetDataOk() (*AppStoreVersionExperimentTreatmentRelationshipsAppStoreVersionExperimentData, bool) {
	if o == nil || IsNil(o.Data) {
		return nil, false
	}
	return o.Data, true
}

// HasData returns a boolean if a field has been set.
func (o *ReviewSubmissionItemCreateRequestDataRelationshipsAppStoreVersionExperiment) HasData() bool {
	if o != nil && !IsNil(o.Data) {
		return true
	}

	return false
}

// SetData gets a reference to the given AppStoreVersionExperimentTreatmentRelationshipsAppStoreVersionExperimentData and assigns it to the Data field.
func (o *ReviewSubmissionItemCreateRequestDataRelationshipsAppStoreVersionExperiment) SetData(v AppStoreVersionExperimentTreatmentRelationshipsAppStoreVersionExperimentData) {
	o.Data = &v
}

func (o ReviewSubmissionItemCreateRequestDataRelationshipsAppStoreVersionExperiment) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o ReviewSubmissionItemCreateRequestDataRelationshipsAppStoreVersionExperiment) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.Data) {
		toSerialize["data"] = o.Data
	}
	return toSerialize, nil
}

type NullableReviewSubmissionItemCreateRequestDataRelationshipsAppStoreVersionExperiment struct {
	value *ReviewSubmissionItemCreateRequestDataRelationshipsAppStoreVersionExperiment
	isSet bool
}

func (v NullableReviewSubmissionItemCreateRequestDataRelationshipsAppStoreVersionExperiment) Get() *ReviewSubmissionItemCreateRequestDataRelationshipsAppStoreVersionExperiment {
	return v.value
}

func (v *NullableReviewSubmissionItemCreateRequestDataRelationshipsAppStoreVersionExperiment) Set(val *ReviewSubmissionItemCreateRequestDataRelationshipsAppStoreVersionExperiment) {
	v.value = val
	v.isSet = true
}

func (v NullableReviewSubmissionItemCreateRequestDataRelationshipsAppStoreVersionExperiment) IsSet() bool {
	return v.isSet
}

func (v *NullableReviewSubmissionItemCreateRequestDataRelationshipsAppStoreVersionExperiment) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableReviewSubmissionItemCreateRequestDataRelationshipsAppStoreVersionExperiment(val *ReviewSubmissionItemCreateRequestDataRelationshipsAppStoreVersionExperiment) *NullableReviewSubmissionItemCreateRequestDataRelationshipsAppStoreVersionExperiment {
	return &NullableReviewSubmissionItemCreateRequestDataRelationshipsAppStoreVersionExperiment{value: val, isSet: true}
}

func (v NullableReviewSubmissionItemCreateRequestDataRelationshipsAppStoreVersionExperiment) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableReviewSubmissionItemCreateRequestDataRelationshipsAppStoreVersionExperiment) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
