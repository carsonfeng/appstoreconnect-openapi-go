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

// checks if the AppInfoUpdateRequestDataRelationshipsPrimaryCategory type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &AppInfoUpdateRequestDataRelationshipsPrimaryCategory{}

// AppInfoUpdateRequestDataRelationshipsPrimaryCategory struct for AppInfoUpdateRequestDataRelationshipsPrimaryCategory
type AppInfoUpdateRequestDataRelationshipsPrimaryCategory struct {
	Data *AppCategoryRelationshipsSubcategoriesDataInner `json:"data,omitempty"`
}

// NewAppInfoUpdateRequestDataRelationshipsPrimaryCategory instantiates a new AppInfoUpdateRequestDataRelationshipsPrimaryCategory object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewAppInfoUpdateRequestDataRelationshipsPrimaryCategory() *AppInfoUpdateRequestDataRelationshipsPrimaryCategory {
	this := AppInfoUpdateRequestDataRelationshipsPrimaryCategory{}
	return &this
}

// NewAppInfoUpdateRequestDataRelationshipsPrimaryCategoryWithDefaults instantiates a new AppInfoUpdateRequestDataRelationshipsPrimaryCategory object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAppInfoUpdateRequestDataRelationshipsPrimaryCategoryWithDefaults() *AppInfoUpdateRequestDataRelationshipsPrimaryCategory {
	this := AppInfoUpdateRequestDataRelationshipsPrimaryCategory{}
	return &this
}

// GetData returns the Data field value if set, zero value otherwise.
func (o *AppInfoUpdateRequestDataRelationshipsPrimaryCategory) GetData() AppCategoryRelationshipsSubcategoriesDataInner {
	if o == nil || IsNil(o.Data) {
		var ret AppCategoryRelationshipsSubcategoriesDataInner
		return ret
	}
	return *o.Data
}

// GetDataOk returns a tuple with the Data field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AppInfoUpdateRequestDataRelationshipsPrimaryCategory) GetDataOk() (*AppCategoryRelationshipsSubcategoriesDataInner, bool) {
	if o == nil || IsNil(o.Data) {
		return nil, false
	}
	return o.Data, true
}

// HasData returns a boolean if a field has been set.
func (o *AppInfoUpdateRequestDataRelationshipsPrimaryCategory) HasData() bool {
	if o != nil && !IsNil(o.Data) {
		return true
	}

	return false
}

// SetData gets a reference to the given AppCategoryRelationshipsSubcategoriesDataInner and assigns it to the Data field.
func (o *AppInfoUpdateRequestDataRelationshipsPrimaryCategory) SetData(v AppCategoryRelationshipsSubcategoriesDataInner) {
	o.Data = &v
}

func (o AppInfoUpdateRequestDataRelationshipsPrimaryCategory) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o AppInfoUpdateRequestDataRelationshipsPrimaryCategory) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.Data) {
		toSerialize["data"] = o.Data
	}
	return toSerialize, nil
}

type NullableAppInfoUpdateRequestDataRelationshipsPrimaryCategory struct {
	value *AppInfoUpdateRequestDataRelationshipsPrimaryCategory
	isSet bool
}

func (v NullableAppInfoUpdateRequestDataRelationshipsPrimaryCategory) Get() *AppInfoUpdateRequestDataRelationshipsPrimaryCategory {
	return v.value
}

func (v *NullableAppInfoUpdateRequestDataRelationshipsPrimaryCategory) Set(val *AppInfoUpdateRequestDataRelationshipsPrimaryCategory) {
	v.value = val
	v.isSet = true
}

func (v NullableAppInfoUpdateRequestDataRelationshipsPrimaryCategory) IsSet() bool {
	return v.isSet
}

func (v *NullableAppInfoUpdateRequestDataRelationshipsPrimaryCategory) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableAppInfoUpdateRequestDataRelationshipsPrimaryCategory(val *AppInfoUpdateRequestDataRelationshipsPrimaryCategory) *NullableAppInfoUpdateRequestDataRelationshipsPrimaryCategory {
	return &NullableAppInfoUpdateRequestDataRelationshipsPrimaryCategory{value: val, isSet: true}
}

func (v NullableAppInfoUpdateRequestDataRelationshipsPrimaryCategory) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableAppInfoUpdateRequestDataRelationshipsPrimaryCategory) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
