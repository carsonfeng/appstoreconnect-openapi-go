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

// checks if the AppStoreReviewAttachment type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &AppStoreReviewAttachment{}

// AppStoreReviewAttachment struct for AppStoreReviewAttachment
type AppStoreReviewAttachment struct {
	Type          string                                 `json:"type"`
	Id            string                                 `json:"id"`
	Attributes    *AppStoreReviewAttachmentAttributes    `json:"attributes,omitempty"`
	Relationships *AppStoreReviewAttachmentRelationships `json:"relationships,omitempty"`
	Links         ResourceLinks                          `json:"links"`
}

// NewAppStoreReviewAttachment instantiates a new AppStoreReviewAttachment object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewAppStoreReviewAttachment(type_ string, id string, links ResourceLinks) *AppStoreReviewAttachment {
	this := AppStoreReviewAttachment{}
	this.Type = type_
	this.Id = id
	this.Links = links
	return &this
}

// NewAppStoreReviewAttachmentWithDefaults instantiates a new AppStoreReviewAttachment object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAppStoreReviewAttachmentWithDefaults() *AppStoreReviewAttachment {
	this := AppStoreReviewAttachment{}
	return &this
}

// GetType returns the Type field value
func (o *AppStoreReviewAttachment) GetType() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Type
}

// GetTypeOk returns a tuple with the Type field value
// and a boolean to check if the value has been set.
func (o *AppStoreReviewAttachment) GetTypeOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Type, true
}

// SetType sets field value
func (o *AppStoreReviewAttachment) SetType(v string) {
	o.Type = v
}

// GetId returns the Id field value
func (o *AppStoreReviewAttachment) GetId() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Id
}

// GetIdOk returns a tuple with the Id field value
// and a boolean to check if the value has been set.
func (o *AppStoreReviewAttachment) GetIdOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Id, true
}

// SetId sets field value
func (o *AppStoreReviewAttachment) SetId(v string) {
	o.Id = v
}

// GetAttributes returns the Attributes field value if set, zero value otherwise.
func (o *AppStoreReviewAttachment) GetAttributes() AppStoreReviewAttachmentAttributes {
	if o == nil || IsNil(o.Attributes) {
		var ret AppStoreReviewAttachmentAttributes
		return ret
	}
	return *o.Attributes
}

// GetAttributesOk returns a tuple with the Attributes field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AppStoreReviewAttachment) GetAttributesOk() (*AppStoreReviewAttachmentAttributes, bool) {
	if o == nil || IsNil(o.Attributes) {
		return nil, false
	}
	return o.Attributes, true
}

// HasAttributes returns a boolean if a field has been set.
func (o *AppStoreReviewAttachment) HasAttributes() bool {
	if o != nil && !IsNil(o.Attributes) {
		return true
	}

	return false
}

// SetAttributes gets a reference to the given AppStoreReviewAttachmentAttributes and assigns it to the Attributes field.
func (o *AppStoreReviewAttachment) SetAttributes(v AppStoreReviewAttachmentAttributes) {
	o.Attributes = &v
}

// GetRelationships returns the Relationships field value if set, zero value otherwise.
func (o *AppStoreReviewAttachment) GetRelationships() AppStoreReviewAttachmentRelationships {
	if o == nil || IsNil(o.Relationships) {
		var ret AppStoreReviewAttachmentRelationships
		return ret
	}
	return *o.Relationships
}

// GetRelationshipsOk returns a tuple with the Relationships field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *AppStoreReviewAttachment) GetRelationshipsOk() (*AppStoreReviewAttachmentRelationships, bool) {
	if o == nil || IsNil(o.Relationships) {
		return nil, false
	}
	return o.Relationships, true
}

// HasRelationships returns a boolean if a field has been set.
func (o *AppStoreReviewAttachment) HasRelationships() bool {
	if o != nil && !IsNil(o.Relationships) {
		return true
	}

	return false
}

// SetRelationships gets a reference to the given AppStoreReviewAttachmentRelationships and assigns it to the Relationships field.
func (o *AppStoreReviewAttachment) SetRelationships(v AppStoreReviewAttachmentRelationships) {
	o.Relationships = &v
}

// GetLinks returns the Links field value
func (o *AppStoreReviewAttachment) GetLinks() ResourceLinks {
	if o == nil {
		var ret ResourceLinks
		return ret
	}

	return o.Links
}

// GetLinksOk returns a tuple with the Links field value
// and a boolean to check if the value has been set.
func (o *AppStoreReviewAttachment) GetLinksOk() (*ResourceLinks, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Links, true
}

// SetLinks sets field value
func (o *AppStoreReviewAttachment) SetLinks(v ResourceLinks) {
	o.Links = v
}

func (o AppStoreReviewAttachment) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o AppStoreReviewAttachment) ToMap() (map[string]interface{}, error) {
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

type NullableAppStoreReviewAttachment struct {
	value *AppStoreReviewAttachment
	isSet bool
}

func (v NullableAppStoreReviewAttachment) Get() *AppStoreReviewAttachment {
	return v.value
}

func (v *NullableAppStoreReviewAttachment) Set(val *AppStoreReviewAttachment) {
	v.value = val
	v.isSet = true
}

func (v NullableAppStoreReviewAttachment) IsSet() bool {
	return v.isSet
}

func (v *NullableAppStoreReviewAttachment) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableAppStoreReviewAttachment(val *AppStoreReviewAttachment) *NullableAppStoreReviewAttachment {
	return &NullableAppStoreReviewAttachment{value: val, isSet: true}
}

func (v NullableAppStoreReviewAttachment) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableAppStoreReviewAttachment) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
