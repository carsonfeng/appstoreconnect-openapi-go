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

// checks if the SubscriptionPrice type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &SubscriptionPrice{}

// SubscriptionPrice struct for SubscriptionPrice
type SubscriptionPrice struct {
	Type          string                                   `json:"type"`
	Id            string                                   `json:"id"`
	Attributes    *SubscriptionPriceAttributes             `json:"attributes,omitempty"`
	Relationships *SubscriptionOfferCodePriceRelationships `json:"relationships,omitempty"`
	Links         ResourceLinks                            `json:"links"`
}

// NewSubscriptionPrice instantiates a new SubscriptionPrice object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewSubscriptionPrice(type_ string, id string, links ResourceLinks) *SubscriptionPrice {
	this := SubscriptionPrice{}
	this.Type = type_
	this.Id = id
	this.Links = links
	return &this
}

// NewSubscriptionPriceWithDefaults instantiates a new SubscriptionPrice object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewSubscriptionPriceWithDefaults() *SubscriptionPrice {
	this := SubscriptionPrice{}
	return &this
}

// GetType returns the Type field value
func (o *SubscriptionPrice) GetType() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Type
}

// GetTypeOk returns a tuple with the Type field value
// and a boolean to check if the value has been set.
func (o *SubscriptionPrice) GetTypeOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Type, true
}

// SetType sets field value
func (o *SubscriptionPrice) SetType(v string) {
	o.Type = v
}

// GetId returns the Id field value
func (o *SubscriptionPrice) GetId() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Id
}

// GetIdOk returns a tuple with the Id field value
// and a boolean to check if the value has been set.
func (o *SubscriptionPrice) GetIdOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Id, true
}

// SetId sets field value
func (o *SubscriptionPrice) SetId(v string) {
	o.Id = v
}

// GetAttributes returns the Attributes field value if set, zero value otherwise.
func (o *SubscriptionPrice) GetAttributes() SubscriptionPriceAttributes {
	if o == nil || IsNil(o.Attributes) {
		var ret SubscriptionPriceAttributes
		return ret
	}
	return *o.Attributes
}

// GetAttributesOk returns a tuple with the Attributes field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *SubscriptionPrice) GetAttributesOk() (*SubscriptionPriceAttributes, bool) {
	if o == nil || IsNil(o.Attributes) {
		return nil, false
	}
	return o.Attributes, true
}

// HasAttributes returns a boolean if a field has been set.
func (o *SubscriptionPrice) HasAttributes() bool {
	if o != nil && !IsNil(o.Attributes) {
		return true
	}

	return false
}

// SetAttributes gets a reference to the given SubscriptionPriceAttributes and assigns it to the Attributes field.
func (o *SubscriptionPrice) SetAttributes(v SubscriptionPriceAttributes) {
	o.Attributes = &v
}

// GetRelationships returns the Relationships field value if set, zero value otherwise.
func (o *SubscriptionPrice) GetRelationships() SubscriptionOfferCodePriceRelationships {
	if o == nil || IsNil(o.Relationships) {
		var ret SubscriptionOfferCodePriceRelationships
		return ret
	}
	return *o.Relationships
}

// GetRelationshipsOk returns a tuple with the Relationships field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *SubscriptionPrice) GetRelationshipsOk() (*SubscriptionOfferCodePriceRelationships, bool) {
	if o == nil || IsNil(o.Relationships) {
		return nil, false
	}
	return o.Relationships, true
}

// HasRelationships returns a boolean if a field has been set.
func (o *SubscriptionPrice) HasRelationships() bool {
	if o != nil && !IsNil(o.Relationships) {
		return true
	}

	return false
}

// SetRelationships gets a reference to the given SubscriptionOfferCodePriceRelationships and assigns it to the Relationships field.
func (o *SubscriptionPrice) SetRelationships(v SubscriptionOfferCodePriceRelationships) {
	o.Relationships = &v
}

// GetLinks returns the Links field value
func (o *SubscriptionPrice) GetLinks() ResourceLinks {
	if o == nil {
		var ret ResourceLinks
		return ret
	}

	return o.Links
}

// GetLinksOk returns a tuple with the Links field value
// and a boolean to check if the value has been set.
func (o *SubscriptionPrice) GetLinksOk() (*ResourceLinks, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Links, true
}

// SetLinks sets field value
func (o *SubscriptionPrice) SetLinks(v ResourceLinks) {
	o.Links = v
}

func (o SubscriptionPrice) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o SubscriptionPrice) ToMap() (map[string]interface{}, error) {
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

type NullableSubscriptionPrice struct {
	value *SubscriptionPrice
	isSet bool
}

func (v NullableSubscriptionPrice) Get() *SubscriptionPrice {
	return v.value
}

func (v *NullableSubscriptionPrice) Set(val *SubscriptionPrice) {
	v.value = val
	v.isSet = true
}

func (v NullableSubscriptionPrice) IsSet() bool {
	return v.isSet
}

func (v *NullableSubscriptionPrice) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableSubscriptionPrice(val *SubscriptionPrice) *NullableSubscriptionPrice {
	return &NullableSubscriptionPrice{value: val, isSet: true}
}

func (v NullableSubscriptionPrice) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableSubscriptionPrice) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
