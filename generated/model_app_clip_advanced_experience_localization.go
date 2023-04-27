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

// checks if the AppClipAdvancedExperienceLocalization type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &AppClipAdvancedExperienceLocalization{}

// AppClipAdvancedExperienceLocalization struct for AppClipAdvancedExperienceLocalization
type AppClipAdvancedExperienceLocalization struct {
	Type       string                                           `json:"type"`
	Id         string                                           `json:"id"`
	Attributes *AppClipAdvancedExperienceLocalizationAttributes `json:"attributes,omitempty"`
	Links      ResourceLinks                                    `json:"links"`
}

// NewAppClipAdvancedExperienceLocalization instantiates a new AppClipAdvancedExperienceLocalization object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewAppClipAdvancedExperienceLocalization(type_ string, id string, links ResourceLinks) *AppClipAdvancedExperienceLocalization {
	this := AppClipAdvancedExperienceLocalization{}
	this.Type = type_
	this.Id = id
	this.Links = links
	return &this
}

// NewAppClipAdvancedExperienceLocalizationWithDefaults instantiates a new AppClipAdvancedExperienceLocalization object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAppClipAdvancedExperienceLocalizationWithDefaults() *AppClipAdvancedExperienceLocalization {
	this := AppClipAdvancedExperienceLocalization{}
	return &this
}

// GetType returns the Type field value
func (o *AppClipAdvancedExperienceLocalization) GetType() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Type
}

// GetTypeOk returns a tuple with the Type field value
// and a boolean to check if the value has been set.
func (o *AppClipAdvancedExperienceLocalization) GetTypeOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Type, true
}

// SetType sets field value
func (o *AppClipAdvancedExperienceLocalization) SetType(v string) {
	o.Type = v
}

// GetId returns the Id field value
func (o *AppClipAdvancedExperienceLocalization) GetId() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Id
}

// GetIdOk returns a tuple with the Id field value
// and a boolean to check if the value has been set.
func (o *AppClipAdvancedExperienceLocalization) GetIdOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Id, true
}

// SetId sets field value
func (o *AppClipAdvancedExperienceLocalization) SetId(v string) {
	o.Id = v
}

// GetAttributes returns the Attributes field value if set, zero value otherwise.
func (o *AppClipAdvancedExperienceLocalization) GetAttributes() AppClipAdvancedExperienceLocalizationAttributes {
	if o == nil || IsNil(o.Attributes) {
		var ret AppClipAdvancedExperienceLocalizationAttributes
		return ret
	}
	return *o.Attributes
}

// GetAttributesOk returns a tuple with the Attributes field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AppClipAdvancedExperienceLocalization) GetAttributesOk() (*AppClipAdvancedExperienceLocalizationAttributes, bool) {
	if o == nil || IsNil(o.Attributes) {
		return nil, false
	}
	return o.Attributes, true
}

// HasAttributes returns a boolean if a field has been set.
func (o *AppClipAdvancedExperienceLocalization) HasAttributes() bool {
	if o != nil && !IsNil(o.Attributes) {
		return true
	}

	return false
}

// SetAttributes gets a reference to the given AppClipAdvancedExperienceLocalizationAttributes and assigns it to the Attributes field.
func (o *AppClipAdvancedExperienceLocalization) SetAttributes(v AppClipAdvancedExperienceLocalizationAttributes) {
	o.Attributes = &v
}

// GetLinks returns the Links field value
func (o *AppClipAdvancedExperienceLocalization) GetLinks() ResourceLinks {
	if o == nil {
		var ret ResourceLinks
		return ret
	}

	return o.Links
}

// GetLinksOk returns a tuple with the Links field value
// and a boolean to check if the value has been set.
func (o *AppClipAdvancedExperienceLocalization) GetLinksOk() (*ResourceLinks, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Links, true
}

// SetLinks sets field value
func (o *AppClipAdvancedExperienceLocalization) SetLinks(v ResourceLinks) {
	o.Links = v
}

func (o AppClipAdvancedExperienceLocalization) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o AppClipAdvancedExperienceLocalization) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["type"] = o.Type
	toSerialize["id"] = o.Id
	if !IsNil(o.Attributes) {
		toSerialize["attributes"] = o.Attributes
	}
	toSerialize["links"] = o.Links
	return toSerialize, nil
}

type NullableAppClipAdvancedExperienceLocalization struct {
	value *AppClipAdvancedExperienceLocalization
	isSet bool
}

func (v NullableAppClipAdvancedExperienceLocalization) Get() *AppClipAdvancedExperienceLocalization {
	return v.value
}

func (v *NullableAppClipAdvancedExperienceLocalization) Set(val *AppClipAdvancedExperienceLocalization) {
	v.value = val
	v.isSet = true
}

func (v NullableAppClipAdvancedExperienceLocalization) IsSet() bool {
	return v.isSet
}

func (v *NullableAppClipAdvancedExperienceLocalization) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableAppClipAdvancedExperienceLocalization(val *AppClipAdvancedExperienceLocalization) *NullableAppClipAdvancedExperienceLocalization {
	return &NullableAppClipAdvancedExperienceLocalization{value: val, isSet: true}
}

func (v NullableAppClipAdvancedExperienceLocalization) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableAppClipAdvancedExperienceLocalization) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
