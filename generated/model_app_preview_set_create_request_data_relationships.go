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

// checks if the AppPreviewSetCreateRequestDataRelationships type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &AppPreviewSetCreateRequestDataRelationships{}

// AppPreviewSetCreateRequestDataRelationships struct for AppPreviewSetCreateRequestDataRelationships
type AppPreviewSetCreateRequestDataRelationships struct {
	AppStoreVersionLocalization                    *AppPreviewSetCreateRequestDataRelationshipsAppStoreVersionLocalization                    `json:"appStoreVersionLocalization,omitempty"`
	AppCustomProductPageLocalization               *AppPreviewSetCreateRequestDataRelationshipsAppCustomProductPageLocalization               `json:"appCustomProductPageLocalization,omitempty"`
	AppStoreVersionExperimentTreatmentLocalization *AppPreviewSetCreateRequestDataRelationshipsAppStoreVersionExperimentTreatmentLocalization `json:"appStoreVersionExperimentTreatmentLocalization,omitempty"`
}

// NewAppPreviewSetCreateRequestDataRelationships instantiates a new AppPreviewSetCreateRequestDataRelationships object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewAppPreviewSetCreateRequestDataRelationships() *AppPreviewSetCreateRequestDataRelationships {
	this := AppPreviewSetCreateRequestDataRelationships{}
	return &this
}

// NewAppPreviewSetCreateRequestDataRelationshipsWithDefaults instantiates a new AppPreviewSetCreateRequestDataRelationships object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAppPreviewSetCreateRequestDataRelationshipsWithDefaults() *AppPreviewSetCreateRequestDataRelationships {
	this := AppPreviewSetCreateRequestDataRelationships{}
	return &this
}

// GetAppStoreVersionLocalization returns the AppStoreVersionLocalization field value if set, zero value otherwise.
func (o *AppPreviewSetCreateRequestDataRelationships) GetAppStoreVersionLocalization() AppPreviewSetCreateRequestDataRelationshipsAppStoreVersionLocalization {
	if o == nil || IsNil(o.AppStoreVersionLocalization) {
		var ret AppPreviewSetCreateRequestDataRelationshipsAppStoreVersionLocalization
		return ret
	}
	return *o.AppStoreVersionLocalization
}

// GetAppStoreVersionLocalizationOk returns a tuple with the AppStoreVersionLocalization field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AppPreviewSetCreateRequestDataRelationships) GetAppStoreVersionLocalizationOk() (*AppPreviewSetCreateRequestDataRelationshipsAppStoreVersionLocalization, bool) {
	if o == nil || IsNil(o.AppStoreVersionLocalization) {
		return nil, false
	}
	return o.AppStoreVersionLocalization, true
}

// HasAppStoreVersionLocalization returns a boolean if a field has been set.
func (o *AppPreviewSetCreateRequestDataRelationships) HasAppStoreVersionLocalization() bool {
	if o != nil && !IsNil(o.AppStoreVersionLocalization) {
		return true
	}

	return false
}

// SetAppStoreVersionLocalization gets a reference to the given AppPreviewSetCreateRequestDataRelationshipsAppStoreVersionLocalization and assigns it to the AppStoreVersionLocalization field.
func (o *AppPreviewSetCreateRequestDataRelationships) SetAppStoreVersionLocalization(v AppPreviewSetCreateRequestDataRelationshipsAppStoreVersionLocalization) {
	o.AppStoreVersionLocalization = &v
}

// GetAppCustomProductPageLocalization returns the AppCustomProductPageLocalization field value if set, zero value otherwise.
func (o *AppPreviewSetCreateRequestDataRelationships) GetAppCustomProductPageLocalization() AppPreviewSetCreateRequestDataRelationshipsAppCustomProductPageLocalization {
	if o == nil || IsNil(o.AppCustomProductPageLocalization) {
		var ret AppPreviewSetCreateRequestDataRelationshipsAppCustomProductPageLocalization
		return ret
	}
	return *o.AppCustomProductPageLocalization
}

// GetAppCustomProductPageLocalizationOk returns a tuple with the AppCustomProductPageLocalization field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AppPreviewSetCreateRequestDataRelationships) GetAppCustomProductPageLocalizationOk() (*AppPreviewSetCreateRequestDataRelationshipsAppCustomProductPageLocalization, bool) {
	if o == nil || IsNil(o.AppCustomProductPageLocalization) {
		return nil, false
	}
	return o.AppCustomProductPageLocalization, true
}

// HasAppCustomProductPageLocalization returns a boolean if a field has been set.
func (o *AppPreviewSetCreateRequestDataRelationships) HasAppCustomProductPageLocalization() bool {
	if o != nil && !IsNil(o.AppCustomProductPageLocalization) {
		return true
	}

	return false
}

// SetAppCustomProductPageLocalization gets a reference to the given AppPreviewSetCreateRequestDataRelationshipsAppCustomProductPageLocalization and assigns it to the AppCustomProductPageLocalization field.
func (o *AppPreviewSetCreateRequestDataRelationships) SetAppCustomProductPageLocalization(v AppPreviewSetCreateRequestDataRelationshipsAppCustomProductPageLocalization) {
	o.AppCustomProductPageLocalization = &v
}

// GetAppStoreVersionExperimentTreatmentLocalization returns the AppStoreVersionExperimentTreatmentLocalization field value if set, zero value otherwise.
func (o *AppPreviewSetCreateRequestDataRelationships) GetAppStoreVersionExperimentTreatmentLocalization() AppPreviewSetCreateRequestDataRelationshipsAppStoreVersionExperimentTreatmentLocalization {
	if o == nil || IsNil(o.AppStoreVersionExperimentTreatmentLocalization) {
		var ret AppPreviewSetCreateRequestDataRelationshipsAppStoreVersionExperimentTreatmentLocalization
		return ret
	}
	return *o.AppStoreVersionExperimentTreatmentLocalization
}

// GetAppStoreVersionExperimentTreatmentLocalizationOk returns a tuple with the AppStoreVersionExperimentTreatmentLocalization field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AppPreviewSetCreateRequestDataRelationships) GetAppStoreVersionExperimentTreatmentLocalizationOk() (*AppPreviewSetCreateRequestDataRelationshipsAppStoreVersionExperimentTreatmentLocalization, bool) {
	if o == nil || IsNil(o.AppStoreVersionExperimentTreatmentLocalization) {
		return nil, false
	}
	return o.AppStoreVersionExperimentTreatmentLocalization, true
}

// HasAppStoreVersionExperimentTreatmentLocalization returns a boolean if a field has been set.
func (o *AppPreviewSetCreateRequestDataRelationships) HasAppStoreVersionExperimentTreatmentLocalization() bool {
	if o != nil && !IsNil(o.AppStoreVersionExperimentTreatmentLocalization) {
		return true
	}

	return false
}

// SetAppStoreVersionExperimentTreatmentLocalization gets a reference to the given AppPreviewSetCreateRequestDataRelationshipsAppStoreVersionExperimentTreatmentLocalization and assigns it to the AppStoreVersionExperimentTreatmentLocalization field.
func (o *AppPreviewSetCreateRequestDataRelationships) SetAppStoreVersionExperimentTreatmentLocalization(v AppPreviewSetCreateRequestDataRelationshipsAppStoreVersionExperimentTreatmentLocalization) {
	o.AppStoreVersionExperimentTreatmentLocalization = &v
}

func (o AppPreviewSetCreateRequestDataRelationships) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o AppPreviewSetCreateRequestDataRelationships) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.AppStoreVersionLocalization) {
		toSerialize["appStoreVersionLocalization"] = o.AppStoreVersionLocalization
	}
	if !IsNil(o.AppCustomProductPageLocalization) {
		toSerialize["appCustomProductPageLocalization"] = o.AppCustomProductPageLocalization
	}
	if !IsNil(o.AppStoreVersionExperimentTreatmentLocalization) {
		toSerialize["appStoreVersionExperimentTreatmentLocalization"] = o.AppStoreVersionExperimentTreatmentLocalization
	}
	return toSerialize, nil
}

type NullableAppPreviewSetCreateRequestDataRelationships struct {
	value *AppPreviewSetCreateRequestDataRelationships
	isSet bool
}

func (v NullableAppPreviewSetCreateRequestDataRelationships) Get() *AppPreviewSetCreateRequestDataRelationships {
	return v.value
}

func (v *NullableAppPreviewSetCreateRequestDataRelationships) Set(val *AppPreviewSetCreateRequestDataRelationships) {
	v.value = val
	v.isSet = true
}

func (v NullableAppPreviewSetCreateRequestDataRelationships) IsSet() bool {
	return v.isSet
}

func (v *NullableAppPreviewSetCreateRequestDataRelationships) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableAppPreviewSetCreateRequestDataRelationships(val *AppPreviewSetCreateRequestDataRelationships) *NullableAppPreviewSetCreateRequestDataRelationships {
	return &NullableAppPreviewSetCreateRequestDataRelationships{value: val, isSet: true}
}

func (v NullableAppPreviewSetCreateRequestDataRelationships) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableAppPreviewSetCreateRequestDataRelationships) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
