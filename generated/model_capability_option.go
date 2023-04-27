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

// checks if the CapabilityOption type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &CapabilityOption{}

// CapabilityOption struct for CapabilityOption
type CapabilityOption struct {
	Key              *string `json:"key,omitempty"`
	Name             *string `json:"name,omitempty"`
	Description      *string `json:"description,omitempty"`
	EnabledByDefault *bool   `json:"enabledByDefault,omitempty"`
	Enabled          *bool   `json:"enabled,omitempty"`
	SupportsWildcard *bool   `json:"supportsWildcard,omitempty"`
}

// NewCapabilityOption instantiates a new CapabilityOption object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewCapabilityOption() *CapabilityOption {
	this := CapabilityOption{}
	return &this
}

// NewCapabilityOptionWithDefaults instantiates a new CapabilityOption object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewCapabilityOptionWithDefaults() *CapabilityOption {
	this := CapabilityOption{}
	return &this
}

// GetKey returns the Key field value if set, zero value otherwise.
func (o *CapabilityOption) GetKey() string {
	if o == nil || IsNil(o.Key) {
		var ret string
		return ret
	}
	return *o.Key
}

// GetKeyOk returns a tuple with the Key field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CapabilityOption) GetKeyOk() (*string, bool) {
	if o == nil || IsNil(o.Key) {
		return nil, false
	}
	return o.Key, true
}

// HasKey returns a boolean if a field has been set.
func (o *CapabilityOption) HasKey() bool {
	if o != nil && !IsNil(o.Key) {
		return true
	}

	return false
}

// SetKey gets a reference to the given string and assigns it to the Key field.
func (o *CapabilityOption) SetKey(v string) {
	o.Key = &v
}

// GetName returns the Name field value if set, zero value otherwise.
func (o *CapabilityOption) GetName() string {
	if o == nil || IsNil(o.Name) {
		var ret string
		return ret
	}
	return *o.Name
}

// GetNameOk returns a tuple with the Name field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CapabilityOption) GetNameOk() (*string, bool) {
	if o == nil || IsNil(o.Name) {
		return nil, false
	}
	return o.Name, true
}

// HasName returns a boolean if a field has been set.
func (o *CapabilityOption) HasName() bool {
	if o != nil && !IsNil(o.Name) {
		return true
	}

	return false
}

// SetName gets a reference to the given string and assigns it to the Name field.
func (o *CapabilityOption) SetName(v string) {
	o.Name = &v
}

// GetDescription returns the Description field value if set, zero value otherwise.
func (o *CapabilityOption) GetDescription() string {
	if o == nil || IsNil(o.Description) {
		var ret string
		return ret
	}
	return *o.Description
}

// GetDescriptionOk returns a tuple with the Description field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CapabilityOption) GetDescriptionOk() (*string, bool) {
	if o == nil || IsNil(o.Description) {
		return nil, false
	}
	return o.Description, true
}

// HasDescription returns a boolean if a field has been set.
func (o *CapabilityOption) HasDescription() bool {
	if o != nil && !IsNil(o.Description) {
		return true
	}

	return false
}

// SetDescription gets a reference to the given string and assigns it to the Description field.
func (o *CapabilityOption) SetDescription(v string) {
	o.Description = &v
}

// GetEnabledByDefault returns the EnabledByDefault field value if set, zero value otherwise.
func (o *CapabilityOption) GetEnabledByDefault() bool {
	if o == nil || IsNil(o.EnabledByDefault) {
		var ret bool
		return ret
	}
	return *o.EnabledByDefault
}

// GetEnabledByDefaultOk returns a tuple with the EnabledByDefault field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CapabilityOption) GetEnabledByDefaultOk() (*bool, bool) {
	if o == nil || IsNil(o.EnabledByDefault) {
		return nil, false
	}
	return o.EnabledByDefault, true
}

// HasEnabledByDefault returns a boolean if a field has been set.
func (o *CapabilityOption) HasEnabledByDefault() bool {
	if o != nil && !IsNil(o.EnabledByDefault) {
		return true
	}

	return false
}

// SetEnabledByDefault gets a reference to the given bool and assigns it to the EnabledByDefault field.
func (o *CapabilityOption) SetEnabledByDefault(v bool) {
	o.EnabledByDefault = &v
}

// GetEnabled returns the Enabled field value if set, zero value otherwise.
func (o *CapabilityOption) GetEnabled() bool {
	if o == nil || IsNil(o.Enabled) {
		var ret bool
		return ret
	}
	return *o.Enabled
}

// GetEnabledOk returns a tuple with the Enabled field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CapabilityOption) GetEnabledOk() (*bool, bool) {
	if o == nil || IsNil(o.Enabled) {
		return nil, false
	}
	return o.Enabled, true
}

// HasEnabled returns a boolean if a field has been set.
func (o *CapabilityOption) HasEnabled() bool {
	if o != nil && !IsNil(o.Enabled) {
		return true
	}

	return false
}

// SetEnabled gets a reference to the given bool and assigns it to the Enabled field.
func (o *CapabilityOption) SetEnabled(v bool) {
	o.Enabled = &v
}

// GetSupportsWildcard returns the SupportsWildcard field value if set, zero value otherwise.
func (o *CapabilityOption) GetSupportsWildcard() bool {
	if o == nil || IsNil(o.SupportsWildcard) {
		var ret bool
		return ret
	}
	return *o.SupportsWildcard
}

// GetSupportsWildcardOk returns a tuple with the SupportsWildcard field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CapabilityOption) GetSupportsWildcardOk() (*bool, bool) {
	if o == nil || IsNil(o.SupportsWildcard) {
		return nil, false
	}
	return o.SupportsWildcard, true
}

// HasSupportsWildcard returns a boolean if a field has been set.
func (o *CapabilityOption) HasSupportsWildcard() bool {
	if o != nil && !IsNil(o.SupportsWildcard) {
		return true
	}

	return false
}

// SetSupportsWildcard gets a reference to the given bool and assigns it to the SupportsWildcard field.
func (o *CapabilityOption) SetSupportsWildcard(v bool) {
	o.SupportsWildcard = &v
}

func (o CapabilityOption) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o CapabilityOption) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.Key) {
		toSerialize["key"] = o.Key
	}
	if !IsNil(o.Name) {
		toSerialize["name"] = o.Name
	}
	if !IsNil(o.Description) {
		toSerialize["description"] = o.Description
	}
	if !IsNil(o.EnabledByDefault) {
		toSerialize["enabledByDefault"] = o.EnabledByDefault
	}
	if !IsNil(o.Enabled) {
		toSerialize["enabled"] = o.Enabled
	}
	if !IsNil(o.SupportsWildcard) {
		toSerialize["supportsWildcard"] = o.SupportsWildcard
	}
	return toSerialize, nil
}

type NullableCapabilityOption struct {
	value *CapabilityOption
	isSet bool
}

func (v NullableCapabilityOption) Get() *CapabilityOption {
	return v.value
}

func (v *NullableCapabilityOption) Set(val *CapabilityOption) {
	v.value = val
	v.isSet = true
}

func (v NullableCapabilityOption) IsSet() bool {
	return v.isSet
}

func (v *NullableCapabilityOption) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableCapabilityOption(val *CapabilityOption) *NullableCapabilityOption {
	return &NullableCapabilityOption{value: val, isSet: true}
}

func (v NullableCapabilityOption) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableCapabilityOption) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
