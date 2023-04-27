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

// checks if the AppStoreVersionExperimentTreatmentLocalizationCreateRequestDataRelationships type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &AppStoreVersionExperimentTreatmentLocalizationCreateRequestDataRelationships{}

// AppStoreVersionExperimentTreatmentLocalizationCreateRequestDataRelationships struct for AppStoreVersionExperimentTreatmentLocalizationCreateRequestDataRelationships
type AppStoreVersionExperimentTreatmentLocalizationCreateRequestDataRelationships struct {
	AppStoreVersionExperimentTreatment AppStoreVersionExperimentTreatmentLocalizationCreateRequestDataRelationshipsAppStoreVersionExperimentTreatment `json:"appStoreVersionExperimentTreatment"`
}

// NewAppStoreVersionExperimentTreatmentLocalizationCreateRequestDataRelationships instantiates a new AppStoreVersionExperimentTreatmentLocalizationCreateRequestDataRelationships object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewAppStoreVersionExperimentTreatmentLocalizationCreateRequestDataRelationships(appStoreVersionExperimentTreatment AppStoreVersionExperimentTreatmentLocalizationCreateRequestDataRelationshipsAppStoreVersionExperimentTreatment) *AppStoreVersionExperimentTreatmentLocalizationCreateRequestDataRelationships {
	this := AppStoreVersionExperimentTreatmentLocalizationCreateRequestDataRelationships{}
	this.AppStoreVersionExperimentTreatment = appStoreVersionExperimentTreatment
	return &this
}

// NewAppStoreVersionExperimentTreatmentLocalizationCreateRequestDataRelationshipsWithDefaults instantiates a new AppStoreVersionExperimentTreatmentLocalizationCreateRequestDataRelationships object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAppStoreVersionExperimentTreatmentLocalizationCreateRequestDataRelationshipsWithDefaults() *AppStoreVersionExperimentTreatmentLocalizationCreateRequestDataRelationships {
	this := AppStoreVersionExperimentTreatmentLocalizationCreateRequestDataRelationships{}
	return &this
}

// GetAppStoreVersionExperimentTreatment returns the AppStoreVersionExperimentTreatment field value
func (o *AppStoreVersionExperimentTreatmentLocalizationCreateRequestDataRelationships) GetAppStoreVersionExperimentTreatment() AppStoreVersionExperimentTreatmentLocalizationCreateRequestDataRelationshipsAppStoreVersionExperimentTreatment {
	if o == nil {
		var ret AppStoreVersionExperimentTreatmentLocalizationCreateRequestDataRelationshipsAppStoreVersionExperimentTreatment
		return ret
	}

	return o.AppStoreVersionExperimentTreatment
}

// GetAppStoreVersionExperimentTreatmentOk returns a tuple with the AppStoreVersionExperimentTreatment field value
// and a boolean to check if the value has been set.
func (o *AppStoreVersionExperimentTreatmentLocalizationCreateRequestDataRelationships) GetAppStoreVersionExperimentTreatmentOk() (*AppStoreVersionExperimentTreatmentLocalizationCreateRequestDataRelationshipsAppStoreVersionExperimentTreatment, bool) {
	if o == nil {
		return nil, false
	}
	return &o.AppStoreVersionExperimentTreatment, true
}

// SetAppStoreVersionExperimentTreatment sets field value
func (o *AppStoreVersionExperimentTreatmentLocalizationCreateRequestDataRelationships) SetAppStoreVersionExperimentTreatment(v AppStoreVersionExperimentTreatmentLocalizationCreateRequestDataRelationshipsAppStoreVersionExperimentTreatment) {
	o.AppStoreVersionExperimentTreatment = v
}

func (o AppStoreVersionExperimentTreatmentLocalizationCreateRequestDataRelationships) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o AppStoreVersionExperimentTreatmentLocalizationCreateRequestDataRelationships) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["appStoreVersionExperimentTreatment"] = o.AppStoreVersionExperimentTreatment
	return toSerialize, nil
}

type NullableAppStoreVersionExperimentTreatmentLocalizationCreateRequestDataRelationships struct {
	value *AppStoreVersionExperimentTreatmentLocalizationCreateRequestDataRelationships
	isSet bool
}

func (v NullableAppStoreVersionExperimentTreatmentLocalizationCreateRequestDataRelationships) Get() *AppStoreVersionExperimentTreatmentLocalizationCreateRequestDataRelationships {
	return v.value
}

func (v *NullableAppStoreVersionExperimentTreatmentLocalizationCreateRequestDataRelationships) Set(val *AppStoreVersionExperimentTreatmentLocalizationCreateRequestDataRelationships) {
	v.value = val
	v.isSet = true
}

func (v NullableAppStoreVersionExperimentTreatmentLocalizationCreateRequestDataRelationships) IsSet() bool {
	return v.isSet
}

func (v *NullableAppStoreVersionExperimentTreatmentLocalizationCreateRequestDataRelationships) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableAppStoreVersionExperimentTreatmentLocalizationCreateRequestDataRelationships(val *AppStoreVersionExperimentTreatmentLocalizationCreateRequestDataRelationships) *NullableAppStoreVersionExperimentTreatmentLocalizationCreateRequestDataRelationships {
	return &NullableAppStoreVersionExperimentTreatmentLocalizationCreateRequestDataRelationships{value: val, isSet: true}
}

func (v NullableAppStoreVersionExperimentTreatmentLocalizationCreateRequestDataRelationships) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableAppStoreVersionExperimentTreatmentLocalizationCreateRequestDataRelationships) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
