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

// checks if the UserUpdateRequestDataAttributes type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &UserUpdateRequestDataAttributes{}

// UserUpdateRequestDataAttributes struct for UserUpdateRequestDataAttributes
type UserUpdateRequestDataAttributes struct {
	Roles               []UserRole `json:"roles,omitempty"`
	AllAppsVisible      *bool      `json:"allAppsVisible,omitempty"`
	ProvisioningAllowed *bool      `json:"provisioningAllowed,omitempty"`
}

// NewUserUpdateRequestDataAttributes instantiates a new UserUpdateRequestDataAttributes object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewUserUpdateRequestDataAttributes() *UserUpdateRequestDataAttributes {
	this := UserUpdateRequestDataAttributes{}
	return &this
}

// NewUserUpdateRequestDataAttributesWithDefaults instantiates a new UserUpdateRequestDataAttributes object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewUserUpdateRequestDataAttributesWithDefaults() *UserUpdateRequestDataAttributes {
	this := UserUpdateRequestDataAttributes{}
	return &this
}

// GetRoles returns the Roles field value if set, zero value otherwise.
func (o *UserUpdateRequestDataAttributes) GetRoles() []UserRole {
	if o == nil || IsNil(o.Roles) {
		var ret []UserRole
		return ret
	}
	return o.Roles
}

// GetRolesOk returns a tuple with the Roles field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *UserUpdateRequestDataAttributes) GetRolesOk() ([]UserRole, bool) {
	if o == nil || IsNil(o.Roles) {
		return nil, false
	}
	return o.Roles, true
}

// HasRoles returns a boolean if a field has been set.
func (o *UserUpdateRequestDataAttributes) HasRoles() bool {
	if o != nil && !IsNil(o.Roles) {
		return true
	}

	return false
}

// SetRoles gets a reference to the given []UserRole and assigns it to the Roles field.
func (o *UserUpdateRequestDataAttributes) SetRoles(v []UserRole) {
	o.Roles = v
}

// GetAllAppsVisible returns the AllAppsVisible field value if set, zero value otherwise.
func (o *UserUpdateRequestDataAttributes) GetAllAppsVisible() bool {
	if o == nil || IsNil(o.AllAppsVisible) {
		var ret bool
		return ret
	}
	return *o.AllAppsVisible
}

// GetAllAppsVisibleOk returns a tuple with the AllAppsVisible field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *UserUpdateRequestDataAttributes) GetAllAppsVisibleOk() (*bool, bool) {
	if o == nil || IsNil(o.AllAppsVisible) {
		return nil, false
	}
	return o.AllAppsVisible, true
}

// HasAllAppsVisible returns a boolean if a field has been set.
func (o *UserUpdateRequestDataAttributes) HasAllAppsVisible() bool {
	if o != nil && !IsNil(o.AllAppsVisible) {
		return true
	}

	return false
}

// SetAllAppsVisible gets a reference to the given bool and assigns it to the AllAppsVisible field.
func (o *UserUpdateRequestDataAttributes) SetAllAppsVisible(v bool) {
	o.AllAppsVisible = &v
}

// GetProvisioningAllowed returns the ProvisioningAllowed field value if set, zero value otherwise.
func (o *UserUpdateRequestDataAttributes) GetProvisioningAllowed() bool {
	if o == nil || IsNil(o.ProvisioningAllowed) {
		var ret bool
		return ret
	}
	return *o.ProvisioningAllowed
}

// GetProvisioningAllowedOk returns a tuple with the ProvisioningAllowed field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *UserUpdateRequestDataAttributes) GetProvisioningAllowedOk() (*bool, bool) {
	if o == nil || IsNil(o.ProvisioningAllowed) {
		return nil, false
	}
	return o.ProvisioningAllowed, true
}

// HasProvisioningAllowed returns a boolean if a field has been set.
func (o *UserUpdateRequestDataAttributes) HasProvisioningAllowed() bool {
	if o != nil && !IsNil(o.ProvisioningAllowed) {
		return true
	}

	return false
}

// SetProvisioningAllowed gets a reference to the given bool and assigns it to the ProvisioningAllowed field.
func (o *UserUpdateRequestDataAttributes) SetProvisioningAllowed(v bool) {
	o.ProvisioningAllowed = &v
}

func (o UserUpdateRequestDataAttributes) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o UserUpdateRequestDataAttributes) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.Roles) {
		toSerialize["roles"] = o.Roles
	}
	if !IsNil(o.AllAppsVisible) {
		toSerialize["allAppsVisible"] = o.AllAppsVisible
	}
	if !IsNil(o.ProvisioningAllowed) {
		toSerialize["provisioningAllowed"] = o.ProvisioningAllowed
	}
	return toSerialize, nil
}

type NullableUserUpdateRequestDataAttributes struct {
	value *UserUpdateRequestDataAttributes
	isSet bool
}

func (v NullableUserUpdateRequestDataAttributes) Get() *UserUpdateRequestDataAttributes {
	return v.value
}

func (v *NullableUserUpdateRequestDataAttributes) Set(val *UserUpdateRequestDataAttributes) {
	v.value = val
	v.isSet = true
}

func (v NullableUserUpdateRequestDataAttributes) IsSet() bool {
	return v.isSet
}

func (v *NullableUserUpdateRequestDataAttributes) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableUserUpdateRequestDataAttributes(val *UserUpdateRequestDataAttributes) *NullableUserUpdateRequestDataAttributes {
	return &NullableUserUpdateRequestDataAttributes{value: val, isSet: true}
}

func (v NullableUserUpdateRequestDataAttributes) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableUserUpdateRequestDataAttributes) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
