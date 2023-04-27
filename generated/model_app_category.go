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

// checks if the AppCategory type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &AppCategory{}

// AppCategory struct for AppCategory
type AppCategory struct {
	Type          string                    `json:"type"`
	Id            string                    `json:"id"`
	Attributes    *AppCategoryAttributes    `json:"attributes,omitempty"`
	Relationships *AppCategoryRelationships `json:"relationships,omitempty"`
	Links         ResourceLinks             `json:"links"`
}

// NewAppCategory instantiates a new AppCategory object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewAppCategory(type_ string, id string, links ResourceLinks) *AppCategory {
	this := AppCategory{}
	this.Type = type_
	this.Id = id
	this.Links = links
	return &this
}

// NewAppCategoryWithDefaults instantiates a new AppCategory object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAppCategoryWithDefaults() *AppCategory {
	this := AppCategory{}
	return &this
}

// GetType returns the Type field value
func (o *AppCategory) GetType() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Type
}

// GetTypeOk returns a tuple with the Type field value
// and a boolean to check if the value has been set.
func (o *AppCategory) GetTypeOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Type, true
}

// SetType sets field value
func (o *AppCategory) SetType(v string) {
	o.Type = v
}

// GetId returns the Id field value
func (o *AppCategory) GetId() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Id
}

// GetIdOk returns a tuple with the Id field value
// and a boolean to check if the value has been set.
func (o *AppCategory) GetIdOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Id, true
}

// SetId sets field value
func (o *AppCategory) SetId(v string) {
	o.Id = v
}

// GetAttributes returns the Attributes field value if set, zero value otherwise.
func (o *AppCategory) GetAttributes() AppCategoryAttributes {
	if o == nil || IsNil(o.Attributes) {
		var ret AppCategoryAttributes
		return ret
	}
	return *o.Attributes
}

// GetAttributesOk returns a tuple with the Attributes field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AppCategory) GetAttributesOk() (*AppCategoryAttributes, bool) {
	if o == nil || IsNil(o.Attributes) {
		return nil, false
	}
	return o.Attributes, true
}

// HasAttributes returns a boolean if a field has been set.
func (o *AppCategory) HasAttributes() bool {
	if o != nil && !IsNil(o.Attributes) {
		return true
	}

	return false
}

// SetAttributes gets a reference to the given AppCategoryAttributes and assigns it to the Attributes field.
func (o *AppCategory) SetAttributes(v AppCategoryAttributes) {
	o.Attributes = &v
}

// GetRelationships returns the Relationships field value if set, zero value otherwise.
func (o *AppCategory) GetRelationships() AppCategoryRelationships {
	if o == nil || IsNil(o.Relationships) {
		var ret AppCategoryRelationships
		return ret
	}
	return *o.Relationships
}

// GetRelationshipsOk returns a tuple with the Relationships field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AppCategory) GetRelationshipsOk() (*AppCategoryRelationships, bool) {
	if o == nil || IsNil(o.Relationships) {
		return nil, false
	}
	return o.Relationships, true
}

// HasRelationships returns a boolean if a field has been set.
func (o *AppCategory) HasRelationships() bool {
	if o != nil && !IsNil(o.Relationships) {
		return true
	}

	return false
}

// SetRelationships gets a reference to the given AppCategoryRelationships and assigns it to the Relationships field.
func (o *AppCategory) SetRelationships(v AppCategoryRelationships) {
	o.Relationships = &v
}

// GetLinks returns the Links field value
func (o *AppCategory) GetLinks() ResourceLinks {
	if o == nil {
		var ret ResourceLinks
		return ret
	}

	return o.Links
}

// GetLinksOk returns a tuple with the Links field value
// and a boolean to check if the value has been set.
func (o *AppCategory) GetLinksOk() (*ResourceLinks, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Links, true
}

// SetLinks sets field value
func (o *AppCategory) SetLinks(v ResourceLinks) {
	o.Links = v
}

func (o AppCategory) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o AppCategory) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["type"] = o.Type
	toSerialize["id"] = o.Id
	if !IsNil(o.Attributes) {
		toSerialize["attributes"] = o.Attributes
	}
	if !IsNil(o.Relationships) {
		toSerialize["relationships"] = o.Relationships
	}
	toSerialize["links"] = o.Links
	return toSerialize, nil
}

type NullableAppCategory struct {
	value *AppCategory
	isSet bool
}

func (v NullableAppCategory) Get() *AppCategory {
	return v.value
}

func (v *NullableAppCategory) Set(val *AppCategory) {
	v.value = val
	v.isSet = true
}

func (v NullableAppCategory) IsSet() bool {
	return v.isSet
}

func (v *NullableAppCategory) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableAppCategory(val *AppCategory) *NullableAppCategory {
	return &NullableAppCategory{value: val, isSet: true}
}

func (v NullableAppCategory) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableAppCategory) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
