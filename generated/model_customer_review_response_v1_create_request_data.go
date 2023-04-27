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

// checks if the CustomerReviewResponseV1CreateRequestData type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &CustomerReviewResponseV1CreateRequestData{}

// CustomerReviewResponseV1CreateRequestData struct for CustomerReviewResponseV1CreateRequestData
type CustomerReviewResponseV1CreateRequestData struct {
	Type          string                                                 `json:"type"`
	Attributes    CustomerReviewResponseV1CreateRequestDataAttributes    `json:"attributes"`
	Relationships CustomerReviewResponseV1CreateRequestDataRelationships `json:"relationships"`
}

// NewCustomerReviewResponseV1CreateRequestData instantiates a new CustomerReviewResponseV1CreateRequestData object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewCustomerReviewResponseV1CreateRequestData(type_ string, attributes CustomerReviewResponseV1CreateRequestDataAttributes, relationships CustomerReviewResponseV1CreateRequestDataRelationships) *CustomerReviewResponseV1CreateRequestData {
	this := CustomerReviewResponseV1CreateRequestData{}
	this.Type = type_
	this.Attributes = attributes
	this.Relationships = relationships
	return &this
}

// NewCustomerReviewResponseV1CreateRequestDataWithDefaults instantiates a new CustomerReviewResponseV1CreateRequestData object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewCustomerReviewResponseV1CreateRequestDataWithDefaults() *CustomerReviewResponseV1CreateRequestData {
	this := CustomerReviewResponseV1CreateRequestData{}
	return &this
}

// GetType returns the Type field value
func (o *CustomerReviewResponseV1CreateRequestData) GetType() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Type
}

// GetTypeOk returns a tuple with the Type field value
// and a boolean to check if the value has been set.
func (o *CustomerReviewResponseV1CreateRequestData) GetTypeOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Type, true
}

// SetType sets field value
func (o *CustomerReviewResponseV1CreateRequestData) SetType(v string) {
	o.Type = v
}

// GetAttributes returns the Attributes field value
func (o *CustomerReviewResponseV1CreateRequestData) GetAttributes() CustomerReviewResponseV1CreateRequestDataAttributes {
	if o == nil {
		var ret CustomerReviewResponseV1CreateRequestDataAttributes
		return ret
	}

	return o.Attributes
}

// GetAttributesOk returns a tuple with the Attributes field value
// and a boolean to check if the value has been set.
func (o *CustomerReviewResponseV1CreateRequestData) GetAttributesOk() (*CustomerReviewResponseV1CreateRequestDataAttributes, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Attributes, true
}

// SetAttributes sets field value
func (o *CustomerReviewResponseV1CreateRequestData) SetAttributes(v CustomerReviewResponseV1CreateRequestDataAttributes) {
	o.Attributes = v
}

// GetRelationships returns the Relationships field value
func (o *CustomerReviewResponseV1CreateRequestData) GetRelationships() CustomerReviewResponseV1CreateRequestDataRelationships {
	if o == nil {
		var ret CustomerReviewResponseV1CreateRequestDataRelationships
		return ret
	}

	return o.Relationships
}

// GetRelationshipsOk returns a tuple with the Relationships field value
// and a boolean to check if the value has been set.
func (o *CustomerReviewResponseV1CreateRequestData) GetRelationshipsOk() (*CustomerReviewResponseV1CreateRequestDataRelationships, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Relationships, true
}

// SetRelationships sets field value
func (o *CustomerReviewResponseV1CreateRequestData) SetRelationships(v CustomerReviewResponseV1CreateRequestDataRelationships) {
	o.Relationships = v
}

func (o CustomerReviewResponseV1CreateRequestData) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o CustomerReviewResponseV1CreateRequestData) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["type"] = o.Type
	toSerialize["attributes"] = o.Attributes
	toSerialize["relationships"] = o.Relationships
	return toSerialize, nil
}

type NullableCustomerReviewResponseV1CreateRequestData struct {
	value *CustomerReviewResponseV1CreateRequestData
	isSet bool
}

func (v NullableCustomerReviewResponseV1CreateRequestData) Get() *CustomerReviewResponseV1CreateRequestData {
	return v.value
}

func (v *NullableCustomerReviewResponseV1CreateRequestData) Set(val *CustomerReviewResponseV1CreateRequestData) {
	v.value = val
	v.isSet = true
}

func (v NullableCustomerReviewResponseV1CreateRequestData) IsSet() bool {
	return v.isSet
}

func (v *NullableCustomerReviewResponseV1CreateRequestData) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableCustomerReviewResponseV1CreateRequestData(val *CustomerReviewResponseV1CreateRequestData) *NullableCustomerReviewResponseV1CreateRequestData {
	return &NullableCustomerReviewResponseV1CreateRequestData{value: val, isSet: true}
}

func (v NullableCustomerReviewResponseV1CreateRequestData) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableCustomerReviewResponseV1CreateRequestData) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
