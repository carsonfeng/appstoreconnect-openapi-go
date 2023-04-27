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

// checks if the GameCenterEnabledVersionAttributes type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &GameCenterEnabledVersionAttributes{}

// GameCenterEnabledVersionAttributes struct for GameCenterEnabledVersionAttributes
type GameCenterEnabledVersionAttributes struct {
	Platform      *Platform   `json:"platform,omitempty"`
	VersionString *string     `json:"versionString,omitempty"`
	IconAsset     *ImageAsset `json:"iconAsset,omitempty"`
}

// NewGameCenterEnabledVersionAttributes instantiates a new GameCenterEnabledVersionAttributes object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewGameCenterEnabledVersionAttributes() *GameCenterEnabledVersionAttributes {
	this := GameCenterEnabledVersionAttributes{}
	return &this
}

// NewGameCenterEnabledVersionAttributesWithDefaults instantiates a new GameCenterEnabledVersionAttributes object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewGameCenterEnabledVersionAttributesWithDefaults() *GameCenterEnabledVersionAttributes {
	this := GameCenterEnabledVersionAttributes{}
	return &this
}

// GetPlatform returns the Platform field value if set, zero value otherwise.
func (o *GameCenterEnabledVersionAttributes) GetPlatform() Platform {
	if o == nil || IsNil(o.Platform) {
		var ret Platform
		return ret
	}
	return *o.Platform
}

// GetPlatformOk returns a tuple with the Platform field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *GameCenterEnabledVersionAttributes) GetPlatformOk() (*Platform, bool) {
	if o == nil || IsNil(o.Platform) {
		return nil, false
	}
	return o.Platform, true
}

// HasPlatform returns a boolean if a field has been set.
func (o *GameCenterEnabledVersionAttributes) HasPlatform() bool {
	if o != nil && !IsNil(o.Platform) {
		return true
	}

	return false
}

// SetPlatform gets a reference to the given Platform and assigns it to the Platform field.
func (o *GameCenterEnabledVersionAttributes) SetPlatform(v Platform) {
	o.Platform = &v
}

// GetVersionString returns the VersionString field value if set, zero value otherwise.
func (o *GameCenterEnabledVersionAttributes) GetVersionString() string {
	if o == nil || IsNil(o.VersionString) {
		var ret string
		return ret
	}
	return *o.VersionString
}

// GetVersionStringOk returns a tuple with the VersionString field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *GameCenterEnabledVersionAttributes) GetVersionStringOk() (*string, bool) {
	if o == nil || IsNil(o.VersionString) {
		return nil, false
	}
	return o.VersionString, true
}

// HasVersionString returns a boolean if a field has been set.
func (o *GameCenterEnabledVersionAttributes) HasVersionString() bool {
	if o != nil && !IsNil(o.VersionString) {
		return true
	}

	return false
}

// SetVersionString gets a reference to the given string and assigns it to the VersionString field.
func (o *GameCenterEnabledVersionAttributes) SetVersionString(v string) {
	o.VersionString = &v
}

// GetIconAsset returns the IconAsset field value if set, zero value otherwise.
func (o *GameCenterEnabledVersionAttributes) GetIconAsset() ImageAsset {
	if o == nil || IsNil(o.IconAsset) {
		var ret ImageAsset
		return ret
	}
	return *o.IconAsset
}

// GetIconAssetOk returns a tuple with the IconAsset field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *GameCenterEnabledVersionAttributes) GetIconAssetOk() (*ImageAsset, bool) {
	if o == nil || IsNil(o.IconAsset) {
		return nil, false
	}
	return o.IconAsset, true
}

// HasIconAsset returns a boolean if a field has been set.
func (o *GameCenterEnabledVersionAttributes) HasIconAsset() bool {
	if o != nil && !IsNil(o.IconAsset) {
		return true
	}

	return false
}

// SetIconAsset gets a reference to the given ImageAsset and assigns it to the IconAsset field.
func (o *GameCenterEnabledVersionAttributes) SetIconAsset(v ImageAsset) {
	o.IconAsset = &v
}

func (o GameCenterEnabledVersionAttributes) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o GameCenterEnabledVersionAttributes) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.Platform) {
		toSerialize["platform"] = o.Platform
	}
	if !IsNil(o.VersionString) {
		toSerialize["versionString"] = o.VersionString
	}
	if !IsNil(o.IconAsset) {
		toSerialize["iconAsset"] = o.IconAsset
	}
	return toSerialize, nil
}

type NullableGameCenterEnabledVersionAttributes struct {
	value *GameCenterEnabledVersionAttributes
	isSet bool
}

func (v NullableGameCenterEnabledVersionAttributes) Get() *GameCenterEnabledVersionAttributes {
	return v.value
}

func (v *NullableGameCenterEnabledVersionAttributes) Set(val *GameCenterEnabledVersionAttributes) {
	v.value = val
	v.isSet = true
}

func (v NullableGameCenterEnabledVersionAttributes) IsSet() bool {
	return v.isSet
}

func (v *NullableGameCenterEnabledVersionAttributes) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableGameCenterEnabledVersionAttributes(val *GameCenterEnabledVersionAttributes) *NullableGameCenterEnabledVersionAttributes {
	return &NullableGameCenterEnabledVersionAttributes{value: val, isSet: true}
}

func (v NullableGameCenterEnabledVersionAttributes) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableGameCenterEnabledVersionAttributes) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
