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

// checks if the AppScreenshotSetRelationships type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &AppScreenshotSetRelationships{}

// AppScreenshotSetRelationships struct for AppScreenshotSetRelationships
type AppScreenshotSetRelationships struct {
	AppStoreVersionLocalization                    *AppPreviewSetRelationshipsAppStoreVersionLocalization                    `json:"appStoreVersionLocalization,omitempty"`
	AppCustomProductPageLocalization               *AppPreviewSetRelationshipsAppCustomProductPageLocalization               `json:"appCustomProductPageLocalization,omitempty"`
	AppStoreVersionExperimentTreatmentLocalization *AppPreviewSetRelationshipsAppStoreVersionExperimentTreatmentLocalization `json:"appStoreVersionExperimentTreatmentLocalization,omitempty"`
	AppScreenshots                                 *AppScreenshotSetRelationshipsAppScreenshots                              `json:"appScreenshots,omitempty"`
}

// NewAppScreenshotSetRelationships instantiates a new AppScreenshotSetRelationships object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewAppScreenshotSetRelationships() *AppScreenshotSetRelationships {
	this := AppScreenshotSetRelationships{}
	return &this
}

// NewAppScreenshotSetRelationshipsWithDefaults instantiates a new AppScreenshotSetRelationships object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAppScreenshotSetRelationshipsWithDefaults() *AppScreenshotSetRelationships {
	this := AppScreenshotSetRelationships{}
	return &this
}

// GetAppStoreVersionLocalization returns the AppStoreVersionLocalization field value if set, zero value otherwise.
func (o *AppScreenshotSetRelationships) GetAppStoreVersionLocalization() AppPreviewSetRelationshipsAppStoreVersionLocalization {
	if o == nil || IsNil(o.AppStoreVersionLocalization) {
		var ret AppPreviewSetRelationshipsAppStoreVersionLocalization
		return ret
	}
	return *o.AppStoreVersionLocalization
}

// GetAppStoreVersionLocalizationOk returns a tuple with the AppStoreVersionLocalization field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AppScreenshotSetRelationships) GetAppStoreVersionLocalizationOk() (*AppPreviewSetRelationshipsAppStoreVersionLocalization, bool) {
	if o == nil || IsNil(o.AppStoreVersionLocalization) {
		return nil, false
	}
	return o.AppStoreVersionLocalization, true
}

// HasAppStoreVersionLocalization returns a boolean if a field has been set.
func (o *AppScreenshotSetRelationships) HasAppStoreVersionLocalization() bool {
	if o != nil && !IsNil(o.AppStoreVersionLocalization) {
		return true
	}

	return false
}

// SetAppStoreVersionLocalization gets a reference to the given AppPreviewSetRelationshipsAppStoreVersionLocalization and assigns it to the AppStoreVersionLocalization field.
func (o *AppScreenshotSetRelationships) SetAppStoreVersionLocalization(v AppPreviewSetRelationshipsAppStoreVersionLocalization) {
	o.AppStoreVersionLocalization = &v
}

// GetAppCustomProductPageLocalization returns the AppCustomProductPageLocalization field value if set, zero value otherwise.
func (o *AppScreenshotSetRelationships) GetAppCustomProductPageLocalization() AppPreviewSetRelationshipsAppCustomProductPageLocalization {
	if o == nil || IsNil(o.AppCustomProductPageLocalization) {
		var ret AppPreviewSetRelationshipsAppCustomProductPageLocalization
		return ret
	}
	return *o.AppCustomProductPageLocalization
}

// GetAppCustomProductPageLocalizationOk returns a tuple with the AppCustomProductPageLocalization field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AppScreenshotSetRelationships) GetAppCustomProductPageLocalizationOk() (*AppPreviewSetRelationshipsAppCustomProductPageLocalization, bool) {
	if o == nil || IsNil(o.AppCustomProductPageLocalization) {
		return nil, false
	}
	return o.AppCustomProductPageLocalization, true
}

// HasAppCustomProductPageLocalization returns a boolean if a field has been set.
func (o *AppScreenshotSetRelationships) HasAppCustomProductPageLocalization() bool {
	if o != nil && !IsNil(o.AppCustomProductPageLocalization) {
		return true
	}

	return false
}

// SetAppCustomProductPageLocalization gets a reference to the given AppPreviewSetRelationshipsAppCustomProductPageLocalization and assigns it to the AppCustomProductPageLocalization field.
func (o *AppScreenshotSetRelationships) SetAppCustomProductPageLocalization(v AppPreviewSetRelationshipsAppCustomProductPageLocalization) {
	o.AppCustomProductPageLocalization = &v
}

// GetAppStoreVersionExperimentTreatmentLocalization returns the AppStoreVersionExperimentTreatmentLocalization field value if set, zero value otherwise.
func (o *AppScreenshotSetRelationships) GetAppStoreVersionExperimentTreatmentLocalization() AppPreviewSetRelationshipsAppStoreVersionExperimentTreatmentLocalization {
	if o == nil || IsNil(o.AppStoreVersionExperimentTreatmentLocalization) {
		var ret AppPreviewSetRelationshipsAppStoreVersionExperimentTreatmentLocalization
		return ret
	}
	return *o.AppStoreVersionExperimentTreatmentLocalization
}

// GetAppStoreVersionExperimentTreatmentLocalizationOk returns a tuple with the AppStoreVersionExperimentTreatmentLocalization field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AppScreenshotSetRelationships) GetAppStoreVersionExperimentTreatmentLocalizationOk() (*AppPreviewSetRelationshipsAppStoreVersionExperimentTreatmentLocalization, bool) {
	if o == nil || IsNil(o.AppStoreVersionExperimentTreatmentLocalization) {
		return nil, false
	}
	return o.AppStoreVersionExperimentTreatmentLocalization, true
}

// HasAppStoreVersionExperimentTreatmentLocalization returns a boolean if a field has been set.
func (o *AppScreenshotSetRelationships) HasAppStoreVersionExperimentTreatmentLocalization() bool {
	if o != nil && !IsNil(o.AppStoreVersionExperimentTreatmentLocalization) {
		return true
	}

	return false
}

// SetAppStoreVersionExperimentTreatmentLocalization gets a reference to the given AppPreviewSetRelationshipsAppStoreVersionExperimentTreatmentLocalization and assigns it to the AppStoreVersionExperimentTreatmentLocalization field.
func (o *AppScreenshotSetRelationships) SetAppStoreVersionExperimentTreatmentLocalization(v AppPreviewSetRelationshipsAppStoreVersionExperimentTreatmentLocalization) {
	o.AppStoreVersionExperimentTreatmentLocalization = &v
}

// GetAppScreenshots returns the AppScreenshots field value if set, zero value otherwise.
func (o *AppScreenshotSetRelationships) GetAppScreenshots() AppScreenshotSetRelationshipsAppScreenshots {
	if o == nil || IsNil(o.AppScreenshots) {
		var ret AppScreenshotSetRelationshipsAppScreenshots
		return ret
	}
	return *o.AppScreenshots
}

// GetAppScreenshotsOk returns a tuple with the AppScreenshots field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AppScreenshotSetRelationships) GetAppScreenshotsOk() (*AppScreenshotSetRelationshipsAppScreenshots, bool) {
	if o == nil || IsNil(o.AppScreenshots) {
		return nil, false
	}
	return o.AppScreenshots, true
}

// HasAppScreenshots returns a boolean if a field has been set.
func (o *AppScreenshotSetRelationships) HasAppScreenshots() bool {
	if o != nil && !IsNil(o.AppScreenshots) {
		return true
	}

	return false
}

// SetAppScreenshots gets a reference to the given AppScreenshotSetRelationshipsAppScreenshots and assigns it to the AppScreenshots field.
func (o *AppScreenshotSetRelationships) SetAppScreenshots(v AppScreenshotSetRelationshipsAppScreenshots) {
	o.AppScreenshots = &v
}

func (o AppScreenshotSetRelationships) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o AppScreenshotSetRelationships) ToMap() (map[string]interface{}, error) {
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
	if !IsNil(o.AppScreenshots) {
		toSerialize["appScreenshots"] = o.AppScreenshots
	}
	return toSerialize, nil
}

type NullableAppScreenshotSetRelationships struct {
	value *AppScreenshotSetRelationships
	isSet bool
}

func (v NullableAppScreenshotSetRelationships) Get() *AppScreenshotSetRelationships {
	return v.value
}

func (v *NullableAppScreenshotSetRelationships) Set(val *AppScreenshotSetRelationships) {
	v.value = val
	v.isSet = true
}

func (v NullableAppScreenshotSetRelationships) IsSet() bool {
	return v.isSet
}

func (v *NullableAppScreenshotSetRelationships) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableAppScreenshotSetRelationships(val *AppScreenshotSetRelationships) *NullableAppScreenshotSetRelationships {
	return &NullableAppScreenshotSetRelationships{value: val, isSet: true}
}

func (v NullableAppScreenshotSetRelationships) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableAppScreenshotSetRelationships) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
