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

// checks if the BuildBundleFileSizeAttributes type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &BuildBundleFileSizeAttributes{}

// BuildBundleFileSizeAttributes struct for BuildBundleFileSizeAttributes
type BuildBundleFileSizeAttributes struct {
	DeviceModel   *string `json:"deviceModel,omitempty"`
	OsVersion     *string `json:"osVersion,omitempty"`
	DownloadBytes *int32  `json:"downloadBytes,omitempty"`
	InstallBytes  *int32  `json:"installBytes,omitempty"`
}

// NewBuildBundleFileSizeAttributes instantiates a new BuildBundleFileSizeAttributes object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewBuildBundleFileSizeAttributes() *BuildBundleFileSizeAttributes {
	this := BuildBundleFileSizeAttributes{}
	return &this
}

// NewBuildBundleFileSizeAttributesWithDefaults instantiates a new BuildBundleFileSizeAttributes object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewBuildBundleFileSizeAttributesWithDefaults() *BuildBundleFileSizeAttributes {
	this := BuildBundleFileSizeAttributes{}
	return &this
}

// GetDeviceModel returns the DeviceModel field value if set, zero value otherwise.
func (o *BuildBundleFileSizeAttributes) GetDeviceModel() string {
	if o == nil || IsNil(o.DeviceModel) {
		var ret string
		return ret
	}
	return *o.DeviceModel
}

// GetDeviceModelOk returns a tuple with the DeviceModel field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *BuildBundleFileSizeAttributes) GetDeviceModelOk() (*string, bool) {
	if o == nil || IsNil(o.DeviceModel) {
		return nil, false
	}
	return o.DeviceModel, true
}

// HasDeviceModel returns a boolean if a field has been set.
func (o *BuildBundleFileSizeAttributes) HasDeviceModel() bool {
	if o != nil && !IsNil(o.DeviceModel) {
		return true
	}

	return false
}

// SetDeviceModel gets a reference to the given string and assigns it to the DeviceModel field.
func (o *BuildBundleFileSizeAttributes) SetDeviceModel(v string) {
	o.DeviceModel = &v
}

// GetOsVersion returns the OsVersion field value if set, zero value otherwise.
func (o *BuildBundleFileSizeAttributes) GetOsVersion() string {
	if o == nil || IsNil(o.OsVersion) {
		var ret string
		return ret
	}
	return *o.OsVersion
}

// GetOsVersionOk returns a tuple with the OsVersion field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *BuildBundleFileSizeAttributes) GetOsVersionOk() (*string, bool) {
	if o == nil || IsNil(o.OsVersion) {
		return nil, false
	}
	return o.OsVersion, true
}

// HasOsVersion returns a boolean if a field has been set.
func (o *BuildBundleFileSizeAttributes) HasOsVersion() bool {
	if o != nil && !IsNil(o.OsVersion) {
		return true
	}

	return false
}

// SetOsVersion gets a reference to the given string and assigns it to the OsVersion field.
func (o *BuildBundleFileSizeAttributes) SetOsVersion(v string) {
	o.OsVersion = &v
}

// GetDownloadBytes returns the DownloadBytes field value if set, zero value otherwise.
func (o *BuildBundleFileSizeAttributes) GetDownloadBytes() int32 {
	if o == nil || IsNil(o.DownloadBytes) {
		var ret int32
		return ret
	}
	return *o.DownloadBytes
}

// GetDownloadBytesOk returns a tuple with the DownloadBytes field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *BuildBundleFileSizeAttributes) GetDownloadBytesOk() (*int32, bool) {
	if o == nil || IsNil(o.DownloadBytes) {
		return nil, false
	}
	return o.DownloadBytes, true
}

// HasDownloadBytes returns a boolean if a field has been set.
func (o *BuildBundleFileSizeAttributes) HasDownloadBytes() bool {
	if o != nil && !IsNil(o.DownloadBytes) {
		return true
	}

	return false
}

// SetDownloadBytes gets a reference to the given int32 and assigns it to the DownloadBytes field.
func (o *BuildBundleFileSizeAttributes) SetDownloadBytes(v int32) {
	o.DownloadBytes = &v
}

// GetInstallBytes returns the InstallBytes field value if set, zero value otherwise.
func (o *BuildBundleFileSizeAttributes) GetInstallBytes() int32 {
	if o == nil || IsNil(o.InstallBytes) {
		var ret int32
		return ret
	}
	return *o.InstallBytes
}

// GetInstallBytesOk returns a tuple with the InstallBytes field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *BuildBundleFileSizeAttributes) GetInstallBytesOk() (*int32, bool) {
	if o == nil || IsNil(o.InstallBytes) {
		return nil, false
	}
	return o.InstallBytes, true
}

// HasInstallBytes returns a boolean if a field has been set.
func (o *BuildBundleFileSizeAttributes) HasInstallBytes() bool {
	if o != nil && !IsNil(o.InstallBytes) {
		return true
	}

	return false
}

// SetInstallBytes gets a reference to the given int32 and assigns it to the InstallBytes field.
func (o *BuildBundleFileSizeAttributes) SetInstallBytes(v int32) {
	o.InstallBytes = &v
}

func (o BuildBundleFileSizeAttributes) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o BuildBundleFileSizeAttributes) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.DeviceModel) {
		toSerialize["deviceModel"] = o.DeviceModel
	}
	if !IsNil(o.OsVersion) {
		toSerialize["osVersion"] = o.OsVersion
	}
	if !IsNil(o.DownloadBytes) {
		toSerialize["downloadBytes"] = o.DownloadBytes
	}
	if !IsNil(o.InstallBytes) {
		toSerialize["installBytes"] = o.InstallBytes
	}
	return toSerialize, nil
}

type NullableBuildBundleFileSizeAttributes struct {
	value *BuildBundleFileSizeAttributes
	isSet bool
}

func (v NullableBuildBundleFileSizeAttributes) Get() *BuildBundleFileSizeAttributes {
	return v.value
}

func (v *NullableBuildBundleFileSizeAttributes) Set(val *BuildBundleFileSizeAttributes) {
	v.value = val
	v.isSet = true
}

func (v NullableBuildBundleFileSizeAttributes) IsSet() bool {
	return v.isSet
}

func (v *NullableBuildBundleFileSizeAttributes) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableBuildBundleFileSizeAttributes(val *BuildBundleFileSizeAttributes) *NullableBuildBundleFileSizeAttributes {
	return &NullableBuildBundleFileSizeAttributes{value: val, isSet: true}
}

func (v NullableBuildBundleFileSizeAttributes) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableBuildBundleFileSizeAttributes) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
