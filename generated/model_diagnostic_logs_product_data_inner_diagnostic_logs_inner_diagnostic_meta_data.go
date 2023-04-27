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

// checks if the DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData{}

// DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData struct for DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData
type DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData struct {
	BundleId             *string `json:"bundleId,omitempty"`
	Event                *string `json:"event,omitempty"`
	OsVersion            *string `json:"osVersion,omitempty"`
	AppVersion           *string `json:"appVersion,omitempty"`
	WritesCaused         *string `json:"writesCaused,omitempty"`
	DeviceType           *string `json:"deviceType,omitempty"`
	PlatformArchitecture *string `json:"platformArchitecture,omitempty"`
	EventDetail          *string `json:"eventDetail,omitempty"`
	BuildVersion         *string `json:"buildVersion,omitempty"`
}

// NewDiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData instantiates a new DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewDiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData() *DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData {
	this := DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData{}
	return &this
}

// NewDiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaDataWithDefaults instantiates a new DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewDiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaDataWithDefaults() *DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData {
	this := DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData{}
	return &this
}

// GetBundleId returns the BundleId field value if set, zero value otherwise.
func (o *DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData) GetBundleId() string {
	if o == nil || IsNil(o.BundleId) {
		var ret string
		return ret
	}
	return *o.BundleId
}

// GetBundleIdOk returns a tuple with the BundleId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData) GetBundleIdOk() (*string, bool) {
	if o == nil || IsNil(o.BundleId) {
		return nil, false
	}
	return o.BundleId, true
}

// HasBundleId returns a boolean if a field has been set.
func (o *DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData) HasBundleId() bool {
	if o != nil && !IsNil(o.BundleId) {
		return true
	}

	return false
}

// SetBundleId gets a reference to the given string and assigns it to the BundleId field.
func (o *DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData) SetBundleId(v string) {
	o.BundleId = &v
}

// GetEvent returns the Event field value if set, zero value otherwise.
func (o *DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData) GetEvent() string {
	if o == nil || IsNil(o.Event) {
		var ret string
		return ret
	}
	return *o.Event
}

// GetEventOk returns a tuple with the Event field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData) GetEventOk() (*string, bool) {
	if o == nil || IsNil(o.Event) {
		return nil, false
	}
	return o.Event, true
}

// HasEvent returns a boolean if a field has been set.
func (o *DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData) HasEvent() bool {
	if o != nil && !IsNil(o.Event) {
		return true
	}

	return false
}

// SetEvent gets a reference to the given string and assigns it to the Event field.
func (o *DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData) SetEvent(v string) {
	o.Event = &v
}

// GetOsVersion returns the OsVersion field value if set, zero value otherwise.
func (o *DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData) GetOsVersion() string {
	if o == nil || IsNil(o.OsVersion) {
		var ret string
		return ret
	}
	return *o.OsVersion
}

// GetOsVersionOk returns a tuple with the OsVersion field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData) GetOsVersionOk() (*string, bool) {
	if o == nil || IsNil(o.OsVersion) {
		return nil, false
	}
	return o.OsVersion, true
}

// HasOsVersion returns a boolean if a field has been set.
func (o *DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData) HasOsVersion() bool {
	if o != nil && !IsNil(o.OsVersion) {
		return true
	}

	return false
}

// SetOsVersion gets a reference to the given string and assigns it to the OsVersion field.
func (o *DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData) SetOsVersion(v string) {
	o.OsVersion = &v
}

// GetAppVersion returns the AppVersion field value if set, zero value otherwise.
func (o *DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData) GetAppVersion() string {
	if o == nil || IsNil(o.AppVersion) {
		var ret string
		return ret
	}
	return *o.AppVersion
}

// GetAppVersionOk returns a tuple with the AppVersion field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData) GetAppVersionOk() (*string, bool) {
	if o == nil || IsNil(o.AppVersion) {
		return nil, false
	}
	return o.AppVersion, true
}

// HasAppVersion returns a boolean if a field has been set.
func (o *DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData) HasAppVersion() bool {
	if o != nil && !IsNil(o.AppVersion) {
		return true
	}

	return false
}

// SetAppVersion gets a reference to the given string and assigns it to the AppVersion field.
func (o *DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData) SetAppVersion(v string) {
	o.AppVersion = &v
}

// GetWritesCaused returns the WritesCaused field value if set, zero value otherwise.
func (o *DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData) GetWritesCaused() string {
	if o == nil || IsNil(o.WritesCaused) {
		var ret string
		return ret
	}
	return *o.WritesCaused
}

// GetWritesCausedOk returns a tuple with the WritesCaused field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData) GetWritesCausedOk() (*string, bool) {
	if o == nil || IsNil(o.WritesCaused) {
		return nil, false
	}
	return o.WritesCaused, true
}

// HasWritesCaused returns a boolean if a field has been set.
func (o *DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData) HasWritesCaused() bool {
	if o != nil && !IsNil(o.WritesCaused) {
		return true
	}

	return false
}

// SetWritesCaused gets a reference to the given string and assigns it to the WritesCaused field.
func (o *DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData) SetWritesCaused(v string) {
	o.WritesCaused = &v
}

// GetDeviceType returns the DeviceType field value if set, zero value otherwise.
func (o *DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData) GetDeviceType() string {
	if o == nil || IsNil(o.DeviceType) {
		var ret string
		return ret
	}
	return *o.DeviceType
}

// GetDeviceTypeOk returns a tuple with the DeviceType field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData) GetDeviceTypeOk() (*string, bool) {
	if o == nil || IsNil(o.DeviceType) {
		return nil, false
	}
	return o.DeviceType, true
}

// HasDeviceType returns a boolean if a field has been set.
func (o *DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData) HasDeviceType() bool {
	if o != nil && !IsNil(o.DeviceType) {
		return true
	}

	return false
}

// SetDeviceType gets a reference to the given string and assigns it to the DeviceType field.
func (o *DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData) SetDeviceType(v string) {
	o.DeviceType = &v
}

// GetPlatformArchitecture returns the PlatformArchitecture field value if set, zero value otherwise.
func (o *DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData) GetPlatformArchitecture() string {
	if o == nil || IsNil(o.PlatformArchitecture) {
		var ret string
		return ret
	}
	return *o.PlatformArchitecture
}

// GetPlatformArchitectureOk returns a tuple with the PlatformArchitecture field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData) GetPlatformArchitectureOk() (*string, bool) {
	if o == nil || IsNil(o.PlatformArchitecture) {
		return nil, false
	}
	return o.PlatformArchitecture, true
}

// HasPlatformArchitecture returns a boolean if a field has been set.
func (o *DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData) HasPlatformArchitecture() bool {
	if o != nil && !IsNil(o.PlatformArchitecture) {
		return true
	}

	return false
}

// SetPlatformArchitecture gets a reference to the given string and assigns it to the PlatformArchitecture field.
func (o *DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData) SetPlatformArchitecture(v string) {
	o.PlatformArchitecture = &v
}

// GetEventDetail returns the EventDetail field value if set, zero value otherwise.
func (o *DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData) GetEventDetail() string {
	if o == nil || IsNil(o.EventDetail) {
		var ret string
		return ret
	}
	return *o.EventDetail
}

// GetEventDetailOk returns a tuple with the EventDetail field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData) GetEventDetailOk() (*string, bool) {
	if o == nil || IsNil(o.EventDetail) {
		return nil, false
	}
	return o.EventDetail, true
}

// HasEventDetail returns a boolean if a field has been set.
func (o *DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData) HasEventDetail() bool {
	if o != nil && !IsNil(o.EventDetail) {
		return true
	}

	return false
}

// SetEventDetail gets a reference to the given string and assigns it to the EventDetail field.
func (o *DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData) SetEventDetail(v string) {
	o.EventDetail = &v
}

// GetBuildVersion returns the BuildVersion field value if set, zero value otherwise.
func (o *DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData) GetBuildVersion() string {
	if o == nil || IsNil(o.BuildVersion) {
		var ret string
		return ret
	}
	return *o.BuildVersion
}

// GetBuildVersionOk returns a tuple with the BuildVersion field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData) GetBuildVersionOk() (*string, bool) {
	if o == nil || IsNil(o.BuildVersion) {
		return nil, false
	}
	return o.BuildVersion, true
}

// HasBuildVersion returns a boolean if a field has been set.
func (o *DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData) HasBuildVersion() bool {
	if o != nil && !IsNil(o.BuildVersion) {
		return true
	}

	return false
}

// SetBuildVersion gets a reference to the given string and assigns it to the BuildVersion field.
func (o *DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData) SetBuildVersion(v string) {
	o.BuildVersion = &v
}

func (o DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.BundleId) {
		toSerialize["bundleId"] = o.BundleId
	}
	if !IsNil(o.Event) {
		toSerialize["event"] = o.Event
	}
	if !IsNil(o.OsVersion) {
		toSerialize["osVersion"] = o.OsVersion
	}
	if !IsNil(o.AppVersion) {
		toSerialize["appVersion"] = o.AppVersion
	}
	if !IsNil(o.WritesCaused) {
		toSerialize["writesCaused"] = o.WritesCaused
	}
	if !IsNil(o.DeviceType) {
		toSerialize["deviceType"] = o.DeviceType
	}
	if !IsNil(o.PlatformArchitecture) {
		toSerialize["platformArchitecture"] = o.PlatformArchitecture
	}
	if !IsNil(o.EventDetail) {
		toSerialize["eventDetail"] = o.EventDetail
	}
	if !IsNil(o.BuildVersion) {
		toSerialize["buildVersion"] = o.BuildVersion
	}
	return toSerialize, nil
}

type NullableDiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData struct {
	value *DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData
	isSet bool
}

func (v NullableDiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData) Get() *DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData {
	return v.value
}

func (v *NullableDiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData) Set(val *DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData) {
	v.value = val
	v.isSet = true
}

func (v NullableDiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData) IsSet() bool {
	return v.isSet
}

func (v *NullableDiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableDiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData(val *DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData) *NullableDiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData {
	return &NullableDiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData{value: val, isSet: true}
}

func (v NullableDiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableDiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
