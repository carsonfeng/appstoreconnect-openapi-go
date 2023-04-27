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

// checks if the BetaAppReviewDetail type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &BetaAppReviewDetail{}

// BetaAppReviewDetail struct for BetaAppReviewDetail
type BetaAppReviewDetail struct {
	Type          string                          `json:"type"`
	Id            string                          `json:"id"`
	Attributes    *AppStoreReviewDetailAttributes `json:"attributes,omitempty"`
	Relationships *AppPreOrderRelationships       `json:"relationships,omitempty"`
	Links         ResourceLinks                   `json:"links"`
}

// NewBetaAppReviewDetail instantiates a new BetaAppReviewDetail object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewBetaAppReviewDetail(type_ string, id string, links ResourceLinks) *BetaAppReviewDetail {
	this := BetaAppReviewDetail{}
	this.Type = type_
	this.Id = id
	this.Links = links
	return &this
}

// NewBetaAppReviewDetailWithDefaults instantiates a new BetaAppReviewDetail object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewBetaAppReviewDetailWithDefaults() *BetaAppReviewDetail {
	this := BetaAppReviewDetail{}
	return &this
}

// GetType returns the Type field value
func (o *BetaAppReviewDetail) GetType() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Type
}

// GetTypeOk returns a tuple with the Type field value
// and a boolean to check if the value has been set.
func (o *BetaAppReviewDetail) GetTypeOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Type, true
}

// SetType sets field value
func (o *BetaAppReviewDetail) SetType(v string) {
	o.Type = v
}

// GetId returns the Id field value
func (o *BetaAppReviewDetail) GetId() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Id
}

// GetIdOk returns a tuple with the Id field value
// and a boolean to check if the value has been set.
func (o *BetaAppReviewDetail) GetIdOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Id, true
}

// SetId sets field value
func (o *BetaAppReviewDetail) SetId(v string) {
	o.Id = v
}

// GetAttributes returns the Attributes field value if set, zero value otherwise.
func (o *BetaAppReviewDetail) GetAttributes() AppStoreReviewDetailAttributes {
	if o == nil || IsNil(o.Attributes) {
		var ret AppStoreReviewDetailAttributes
		return ret
	}
	return *o.Attributes
}

// GetAttributesOk returns a tuple with the Attributes field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *BetaAppReviewDetail) GetAttributesOk() (*AppStoreReviewDetailAttributes, bool) {
	if o == nil || IsNil(o.Attributes) {
		return nil, false
	}
	return o.Attributes, true
}

// HasAttributes returns a boolean if a field has been set.
func (o *BetaAppReviewDetail) HasAttributes() bool {
	if o != nil && !IsNil(o.Attributes) {
		return true
	}

	return false
}

// SetAttributes gets a reference to the given AppStoreReviewDetailAttributes and assigns it to the Attributes field.
func (o *BetaAppReviewDetail) SetAttributes(v AppStoreReviewDetailAttributes) {
	o.Attributes = &v
}

// GetRelationships returns the Relationships field value if set, zero value otherwise.
func (o *BetaAppReviewDetail) GetRelationships() AppPreOrderRelationships {
	if o == nil || IsNil(o.Relationships) {
		var ret AppPreOrderRelationships
		return ret
	}
	return *o.Relationships
}

// GetRelationshipsOk returns a tuple with the Relationships field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *BetaAppReviewDetail) GetRelationshipsOk() (*AppPreOrderRelationships, bool) {
	if o == nil || IsNil(o.Relationships) {
		return nil, false
	}
	return o.Relationships, true
}

// HasRelationships returns a boolean if a field has been set.
func (o *BetaAppReviewDetail) HasRelationships() bool {
	if o != nil && !IsNil(o.Relationships) {
		return true
	}

	return false
}

// SetRelationships gets a reference to the given AppPreOrderRelationships and assigns it to the Relationships field.
func (o *BetaAppReviewDetail) SetRelationships(v AppPreOrderRelationships) {
	o.Relationships = &v
}

// GetLinks returns the Links field value
func (o *BetaAppReviewDetail) GetLinks() ResourceLinks {
	if o == nil {
		var ret ResourceLinks
		return ret
	}

	return o.Links
}

// GetLinksOk returns a tuple with the Links field value
// and a boolean to check if the value has been set.
func (o *BetaAppReviewDetail) GetLinksOk() (*ResourceLinks, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Links, true
}

// SetLinks sets field value
func (o *BetaAppReviewDetail) SetLinks(v ResourceLinks) {
	o.Links = v
}

func (o BetaAppReviewDetail) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o BetaAppReviewDetail) ToMap() (map[string]interface{}, error) {
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

type NullableBetaAppReviewDetail struct {
	value *BetaAppReviewDetail
	isSet bool
}

func (v NullableBetaAppReviewDetail) Get() *BetaAppReviewDetail {
	return v.value
}

func (v *NullableBetaAppReviewDetail) Set(val *BetaAppReviewDetail) {
	v.value = val
	v.isSet = true
}

func (v NullableBetaAppReviewDetail) IsSet() bool {
	return v.isSet
}

func (v *NullableBetaAppReviewDetail) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableBetaAppReviewDetail(val *BetaAppReviewDetail) *NullableBetaAppReviewDetail {
	return &NullableBetaAppReviewDetail{value: val, isSet: true}
}

func (v NullableBetaAppReviewDetail) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableBetaAppReviewDetail) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
