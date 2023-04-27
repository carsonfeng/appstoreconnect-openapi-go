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

// checks if the InAppPurchaseLocalization type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &InAppPurchaseLocalization{}

// InAppPurchaseLocalization struct for InAppPurchaseLocalization
type InAppPurchaseLocalization struct {
	Type          string                                              `json:"type"`
	Id            string                                              `json:"id"`
	Attributes    *InAppPurchaseLocalizationAttributes                `json:"attributes,omitempty"`
	Relationships *InAppPurchaseAppStoreReviewScreenshotRelationships `json:"relationships,omitempty"`
	Links         ResourceLinks                                       `json:"links"`
}

// NewInAppPurchaseLocalization instantiates a new InAppPurchaseLocalization object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewInAppPurchaseLocalization(type_ string, id string, links ResourceLinks) *InAppPurchaseLocalization {
	this := InAppPurchaseLocalization{}
	this.Type = type_
	this.Id = id
	this.Links = links
	return &this
}

// NewInAppPurchaseLocalizationWithDefaults instantiates a new InAppPurchaseLocalization object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewInAppPurchaseLocalizationWithDefaults() *InAppPurchaseLocalization {
	this := InAppPurchaseLocalization{}
	return &this
}

// GetType returns the Type field value
func (o *InAppPurchaseLocalization) GetType() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Type
}

// GetTypeOk returns a tuple with the Type field value
// and a boolean to check if the value has been set.
func (o *InAppPurchaseLocalization) GetTypeOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Type, true
}

// SetType sets field value
func (o *InAppPurchaseLocalization) SetType(v string) {
	o.Type = v
}

// GetId returns the Id field value
func (o *InAppPurchaseLocalization) GetId() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Id
}

// GetIdOk returns a tuple with the Id field value
// and a boolean to check if the value has been set.
func (o *InAppPurchaseLocalization) GetIdOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Id, true
}

// SetId sets field value
func (o *InAppPurchaseLocalization) SetId(v string) {
	o.Id = v
}

// GetAttributes returns the Attributes field value if set, zero value otherwise.
func (o *InAppPurchaseLocalization) GetAttributes() InAppPurchaseLocalizationAttributes {
	if o == nil || IsNil(o.Attributes) {
		var ret InAppPurchaseLocalizationAttributes
		return ret
	}
	return *o.Attributes
}

// GetAttributesOk returns a tuple with the Attributes field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *InAppPurchaseLocalization) GetAttributesOk() (*InAppPurchaseLocalizationAttributes, bool) {
	if o == nil || IsNil(o.Attributes) {
		return nil, false
	}
	return o.Attributes, true
}

// HasAttributes returns a boolean if a field has been set.
func (o *InAppPurchaseLocalization) HasAttributes() bool {
	if o != nil && !IsNil(o.Attributes) {
		return true
	}

	return false
}

// SetAttributes gets a reference to the given InAppPurchaseLocalizationAttributes and assigns it to the Attributes field.
func (o *InAppPurchaseLocalization) SetAttributes(v InAppPurchaseLocalizationAttributes) {
	o.Attributes = &v
}

// GetRelationships returns the Relationships field value if set, zero value otherwise.
func (o *InAppPurchaseLocalization) GetRelationships() InAppPurchaseAppStoreReviewScreenshotRelationships {
	if o == nil || IsNil(o.Relationships) {
		var ret InAppPurchaseAppStoreReviewScreenshotRelationships
		return ret
	}
	return *o.Relationships
}

// GetRelationshipsOk returns a tuple with the Relationships field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *InAppPurchaseLocalization) GetRelationshipsOk() (*InAppPurchaseAppStoreReviewScreenshotRelationships, bool) {
	if o == nil || IsNil(o.Relationships) {
		return nil, false
	}
	return o.Relationships, true
}

// HasRelationships returns a boolean if a field has been set.
func (o *InAppPurchaseLocalization) HasRelationships() bool {
	if o != nil && !IsNil(o.Relationships) {
		return true
	}

	return false
}

// SetRelationships gets a reference to the given InAppPurchaseAppStoreReviewScreenshotRelationships and assigns it to the Relationships field.
func (o *InAppPurchaseLocalization) SetRelationships(v InAppPurchaseAppStoreReviewScreenshotRelationships) {
	o.Relationships = &v
}

// GetLinks returns the Links field value
func (o *InAppPurchaseLocalization) GetLinks() ResourceLinks {
	if o == nil {
		var ret ResourceLinks
		return ret
	}

	return o.Links
}

// GetLinksOk returns a tuple with the Links field value
// and a boolean to check if the value has been set.
func (o *InAppPurchaseLocalization) GetLinksOk() (*ResourceLinks, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Links, true
}

// SetLinks sets field value
func (o *InAppPurchaseLocalization) SetLinks(v ResourceLinks) {
	o.Links = v
}

func (o InAppPurchaseLocalization) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o InAppPurchaseLocalization) ToMap() (map[string]interface{}, error) {
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

type NullableInAppPurchaseLocalization struct {
	value *InAppPurchaseLocalization
	isSet bool
}

func (v NullableInAppPurchaseLocalization) Get() *InAppPurchaseLocalization {
	return v.value
}

func (v *NullableInAppPurchaseLocalization) Set(val *InAppPurchaseLocalization) {
	v.value = val
	v.isSet = true
}

func (v NullableInAppPurchaseLocalization) IsSet() bool {
	return v.isSet
}

func (v *NullableInAppPurchaseLocalization) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableInAppPurchaseLocalization(val *InAppPurchaseLocalization) *NullableInAppPurchaseLocalization {
	return &NullableInAppPurchaseLocalization{value: val, isSet: true}
}

func (v NullableInAppPurchaseLocalization) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableInAppPurchaseLocalization) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
