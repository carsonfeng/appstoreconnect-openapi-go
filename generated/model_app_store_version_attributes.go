/*
App Store Connect API

No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)

API version: 2.3
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package openapi

import (
	"encoding/json"
	"time"
)

// checks if the AppStoreVersionAttributes type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &AppStoreVersionAttributes{}

// AppStoreVersionAttributes struct for AppStoreVersionAttributes
type AppStoreVersionAttributes struct {
	Platform            *Platform             `json:"platform,omitempty"`
	VersionString       *string               `json:"versionString,omitempty"`
	AppStoreState       *AppStoreVersionState `json:"appStoreState,omitempty"`
	Copyright           *string               `json:"copyright,omitempty"`
	ReleaseType         *string               `json:"releaseType,omitempty"`
	EarliestReleaseDate *time.Time            `json:"earliestReleaseDate,omitempty"`
	Downloadable        *bool                 `json:"downloadable,omitempty"`
	CreatedDate         *time.Time            `json:"createdDate,omitempty"`
}

// NewAppStoreVersionAttributes instantiates a new AppStoreVersionAttributes object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewAppStoreVersionAttributes() *AppStoreVersionAttributes {
	this := AppStoreVersionAttributes{}
	return &this
}

// NewAppStoreVersionAttributesWithDefaults instantiates a new AppStoreVersionAttributes object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAppStoreVersionAttributesWithDefaults() *AppStoreVersionAttributes {
	this := AppStoreVersionAttributes{}
	return &this
}

// GetPlatform returns the Platform field value if set, zero value otherwise.
func (o *AppStoreVersionAttributes) GetPlatform() Platform {
	if o == nil || IsNil(o.Platform) {
		var ret Platform
		return ret
	}
	return *o.Platform
}

// GetPlatformOk returns a tuple with the Platform field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AppStoreVersionAttributes) GetPlatformOk() (*Platform, bool) {
	if o == nil || IsNil(o.Platform) {
		return nil, false
	}
	return o.Platform, true
}

// HasPlatform returns a boolean if a field has been set.
func (o *AppStoreVersionAttributes) HasPlatform() bool {
	if o != nil && !IsNil(o.Platform) {
		return true
	}

	return false
}

// SetPlatform gets a reference to the given Platform and assigns it to the Platform field.
func (o *AppStoreVersionAttributes) SetPlatform(v Platform) {
	o.Platform = &v
}

// GetVersionString returns the VersionString field value if set, zero value otherwise.
func (o *AppStoreVersionAttributes) GetVersionString() string {
	if o == nil || IsNil(o.VersionString) {
		var ret string
		return ret
	}
	return *o.VersionString
}

// GetVersionStringOk returns a tuple with the VersionString field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AppStoreVersionAttributes) GetVersionStringOk() (*string, bool) {
	if o == nil || IsNil(o.VersionString) {
		return nil, false
	}
	return o.VersionString, true
}

// HasVersionString returns a boolean if a field has been set.
func (o *AppStoreVersionAttributes) HasVersionString() bool {
	if o != nil && !IsNil(o.VersionString) {
		return true
	}

	return false
}

// SetVersionString gets a reference to the given string and assigns it to the VersionString field.
func (o *AppStoreVersionAttributes) SetVersionString(v string) {
	o.VersionString = &v
}

// GetAppStoreState returns the AppStoreState field value if set, zero value otherwise.
func (o *AppStoreVersionAttributes) GetAppStoreState() AppStoreVersionState {
	if o == nil || IsNil(o.AppStoreState) {
		var ret AppStoreVersionState
		return ret
	}
	return *o.AppStoreState
}

// GetAppStoreStateOk returns a tuple with the AppStoreState field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AppStoreVersionAttributes) GetAppStoreStateOk() (*AppStoreVersionState, bool) {
	if o == nil || IsNil(o.AppStoreState) {
		return nil, false
	}
	return o.AppStoreState, true
}

// HasAppStoreState returns a boolean if a field has been set.
func (o *AppStoreVersionAttributes) HasAppStoreState() bool {
	if o != nil && !IsNil(o.AppStoreState) {
		return true
	}

	return false
}

// SetAppStoreState gets a reference to the given AppStoreVersionState and assigns it to the AppStoreState field.
func (o *AppStoreVersionAttributes) SetAppStoreState(v AppStoreVersionState) {
	o.AppStoreState = &v
}

// GetCopyright returns the Copyright field value if set, zero value otherwise.
func (o *AppStoreVersionAttributes) GetCopyright() string {
	if o == nil || IsNil(o.Copyright) {
		var ret string
		return ret
	}
	return *o.Copyright
}

// GetCopyrightOk returns a tuple with the Copyright field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AppStoreVersionAttributes) GetCopyrightOk() (*string, bool) {
	if o == nil || IsNil(o.Copyright) {
		return nil, false
	}
	return o.Copyright, true
}

// HasCopyright returns a boolean if a field has been set.
func (o *AppStoreVersionAttributes) HasCopyright() bool {
	if o != nil && !IsNil(o.Copyright) {
		return true
	}

	return false
}

// SetCopyright gets a reference to the given string and assigns it to the Copyright field.
func (o *AppStoreVersionAttributes) SetCopyright(v string) {
	o.Copyright = &v
}

// GetReleaseType returns the ReleaseType field value if set, zero value otherwise.
func (o *AppStoreVersionAttributes) GetReleaseType() string {
	if o == nil || IsNil(o.ReleaseType) {
		var ret string
		return ret
	}
	return *o.ReleaseType
}

// GetReleaseTypeOk returns a tuple with the ReleaseType field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AppStoreVersionAttributes) GetReleaseTypeOk() (*string, bool) {
	if o == nil || IsNil(o.ReleaseType) {
		return nil, false
	}
	return o.ReleaseType, true
}

// HasReleaseType returns a boolean if a field has been set.
func (o *AppStoreVersionAttributes) HasReleaseType() bool {
	if o != nil && !IsNil(o.ReleaseType) {
		return true
	}

	return false
}

// SetReleaseType gets a reference to the given string and assigns it to the ReleaseType field.
func (o *AppStoreVersionAttributes) SetReleaseType(v string) {
	o.ReleaseType = &v
}

// GetEarliestReleaseDate returns the EarliestReleaseDate field value if set, zero value otherwise.
func (o *AppStoreVersionAttributes) GetEarliestReleaseDate() time.Time {
	if o == nil || IsNil(o.EarliestReleaseDate) {
		var ret time.Time
		return ret
	}
	return *o.EarliestReleaseDate
}

// GetEarliestReleaseDateOk returns a tuple with the EarliestReleaseDate field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AppStoreVersionAttributes) GetEarliestReleaseDateOk() (*time.Time, bool) {
	if o == nil || IsNil(o.EarliestReleaseDate) {
		return nil, false
	}
	return o.EarliestReleaseDate, true
}

// HasEarliestReleaseDate returns a boolean if a field has been set.
func (o *AppStoreVersionAttributes) HasEarliestReleaseDate() bool {
	if o != nil && !IsNil(o.EarliestReleaseDate) {
		return true
	}

	return false
}

// SetEarliestReleaseDate gets a reference to the given time.Time and assigns it to the EarliestReleaseDate field.
func (o *AppStoreVersionAttributes) SetEarliestReleaseDate(v time.Time) {
	o.EarliestReleaseDate = &v
}

// GetDownloadable returns the Downloadable field value if set, zero value otherwise.
func (o *AppStoreVersionAttributes) GetDownloadable() bool {
	if o == nil || IsNil(o.Downloadable) {
		var ret bool
		return ret
	}
	return *o.Downloadable
}

// GetDownloadableOk returns a tuple with the Downloadable field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AppStoreVersionAttributes) GetDownloadableOk() (*bool, bool) {
	if o == nil || IsNil(o.Downloadable) {
		return nil, false
	}
	return o.Downloadable, true
}

// HasDownloadable returns a boolean if a field has been set.
func (o *AppStoreVersionAttributes) HasDownloadable() bool {
	if o != nil && !IsNil(o.Downloadable) {
		return true
	}

	return false
}

// SetDownloadable gets a reference to the given bool and assigns it to the Downloadable field.
func (o *AppStoreVersionAttributes) SetDownloadable(v bool) {
	o.Downloadable = &v
}

// GetCreatedDate returns the CreatedDate field value if set, zero value otherwise.
func (o *AppStoreVersionAttributes) GetCreatedDate() time.Time {
	if o == nil || IsNil(o.CreatedDate) {
		var ret time.Time
		return ret
	}
	return *o.CreatedDate
}

// GetCreatedDateOk returns a tuple with the CreatedDate field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AppStoreVersionAttributes) GetCreatedDateOk() (*time.Time, bool) {
	if o == nil || IsNil(o.CreatedDate) {
		return nil, false
	}
	return o.CreatedDate, true
}

// HasCreatedDate returns a boolean if a field has been set.
func (o *AppStoreVersionAttributes) HasCreatedDate() bool {
	if o != nil && !IsNil(o.CreatedDate) {
		return true
	}

	return false
}

// SetCreatedDate gets a reference to the given time.Time and assigns it to the CreatedDate field.
func (o *AppStoreVersionAttributes) SetCreatedDate(v time.Time) {
	o.CreatedDate = &v
}

func (o AppStoreVersionAttributes) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o AppStoreVersionAttributes) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.Platform) {
		toSerialize["platform"] = o.Platform
	}
	if !IsNil(o.VersionString) {
		toSerialize["versionString"] = o.VersionString
	}
	if !IsNil(o.AppStoreState) {
		toSerialize["appStoreState"] = o.AppStoreState
	}
	if !IsNil(o.Copyright) {
		toSerialize["copyright"] = o.Copyright
	}
	if !IsNil(o.ReleaseType) {
		toSerialize["releaseType"] = o.ReleaseType
	}
	if !IsNil(o.EarliestReleaseDate) {
		toSerialize["earliestReleaseDate"] = o.EarliestReleaseDate
	}
	if !IsNil(o.Downloadable) {
		toSerialize["downloadable"] = o.Downloadable
	}
	if !IsNil(o.CreatedDate) {
		toSerialize["createdDate"] = o.CreatedDate
	}
	return toSerialize, nil
}

type NullableAppStoreVersionAttributes struct {
	value *AppStoreVersionAttributes
	isSet bool
}

func (v NullableAppStoreVersionAttributes) Get() *AppStoreVersionAttributes {
	return v.value
}

func (v *NullableAppStoreVersionAttributes) Set(val *AppStoreVersionAttributes) {
	v.value = val
	v.isSet = true
}

func (v NullableAppStoreVersionAttributes) IsSet() bool {
	return v.isSet
}

func (v *NullableAppStoreVersionAttributes) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableAppStoreVersionAttributes(val *AppStoreVersionAttributes) *NullableAppStoreVersionAttributes {
	return &NullableAppStoreVersionAttributes{value: val, isSet: true}
}

func (v NullableAppStoreVersionAttributes) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableAppStoreVersionAttributes) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
