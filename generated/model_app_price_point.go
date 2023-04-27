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

// checks if the AppPricePoint type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &AppPricePoint{}

// AppPricePoint struct for AppPricePoint
type AppPricePoint struct {
	Type          string                      `json:"type"`
	Id            string                      `json:"id"`
	Attributes    *AppPricePointV2Attributes  `json:"attributes,omitempty"`
	Relationships *AppPricePointRelationships `json:"relationships,omitempty"`
	Links         ResourceLinks               `json:"links"`
}

// NewAppPricePoint instantiates a new AppPricePoint object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewAppPricePoint(type_ string, id string, links ResourceLinks) *AppPricePoint {
	this := AppPricePoint{}
	this.Type = type_
	this.Id = id
	this.Links = links
	return &this
}

// NewAppPricePointWithDefaults instantiates a new AppPricePoint object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAppPricePointWithDefaults() *AppPricePoint {
	this := AppPricePoint{}
	return &this
}

// GetType returns the Type field value
func (o *AppPricePoint) GetType() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Type
}

// GetTypeOk returns a tuple with the Type field value
// and a boolean to check if the value has been set.
func (o *AppPricePoint) GetTypeOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Type, true
}

// SetType sets field value
func (o *AppPricePoint) SetType(v string) {
	o.Type = v
}

// GetId returns the Id field value
func (o *AppPricePoint) GetId() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Id
}

// GetIdOk returns a tuple with the Id field value
// and a boolean to check if the value has been set.
func (o *AppPricePoint) GetIdOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Id, true
}

// SetId sets field value
func (o *AppPricePoint) SetId(v string) {
	o.Id = v
}

// GetAttributes returns the Attributes field value if set, zero value otherwise.
func (o *AppPricePoint) GetAttributes() AppPricePointV2Attributes {
	if o == nil || IsNil(o.Attributes) {
		var ret AppPricePointV2Attributes
		return ret
	}
	return *o.Attributes
}

// GetAttributesOk returns a tuple with the Attributes field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AppPricePoint) GetAttributesOk() (*AppPricePointV2Attributes, bool) {
	if o == nil || IsNil(o.Attributes) {
		return nil, false
	}
	return o.Attributes, true
}

// HasAttributes returns a boolean if a field has been set.
func (o *AppPricePoint) HasAttributes() bool {
	if o != nil && !IsNil(o.Attributes) {
		return true
	}

	return false
}

// SetAttributes gets a reference to the given AppPricePointV2Attributes and assigns it to the Attributes field.
func (o *AppPricePoint) SetAttributes(v AppPricePointV2Attributes) {
	o.Attributes = &v
}

// GetRelationships returns the Relationships field value if set, zero value otherwise.
func (o *AppPricePoint) GetRelationships() AppPricePointRelationships {
	if o == nil || IsNil(o.Relationships) {
		var ret AppPricePointRelationships
		return ret
	}
	return *o.Relationships
}

// GetRelationshipsOk returns a tuple with the Relationships field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AppPricePoint) GetRelationshipsOk() (*AppPricePointRelationships, bool) {
	if o == nil || IsNil(o.Relationships) {
		return nil, false
	}
	return o.Relationships, true
}

// HasRelationships returns a boolean if a field has been set.
func (o *AppPricePoint) HasRelationships() bool {
	if o != nil && !IsNil(o.Relationships) {
		return true
	}

	return false
}

// SetRelationships gets a reference to the given AppPricePointRelationships and assigns it to the Relationships field.
func (o *AppPricePoint) SetRelationships(v AppPricePointRelationships) {
	o.Relationships = &v
}

// GetLinks returns the Links field value
func (o *AppPricePoint) GetLinks() ResourceLinks {
	if o == nil {
		var ret ResourceLinks
		return ret
	}

	return o.Links
}

// GetLinksOk returns a tuple with the Links field value
// and a boolean to check if the value has been set.
func (o *AppPricePoint) GetLinksOk() (*ResourceLinks, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Links, true
}

// SetLinks sets field value
func (o *AppPricePoint) SetLinks(v ResourceLinks) {
	o.Links = v
}

func (o AppPricePoint) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o AppPricePoint) ToMap() (map[string]interface{}, error) {
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

type NullableAppPricePoint struct {
	value *AppPricePoint
	isSet bool
}

func (v NullableAppPricePoint) Get() *AppPricePoint {
	return v.value
}

func (v *NullableAppPricePoint) Set(val *AppPricePoint) {
	v.value = val
	v.isSet = true
}

func (v NullableAppPricePoint) IsSet() bool {
	return v.isSet
}

func (v *NullableAppPricePoint) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableAppPricePoint(val *AppPricePoint) *NullableAppPricePoint {
	return &NullableAppPricePoint{value: val, isSet: true}
}

func (v NullableAppPricePoint) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableAppPricePoint) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
