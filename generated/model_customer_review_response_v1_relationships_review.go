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

// checks if the CustomerReviewResponseV1RelationshipsReview type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &CustomerReviewResponseV1RelationshipsReview{}

// CustomerReviewResponseV1RelationshipsReview struct for CustomerReviewResponseV1RelationshipsReview
type CustomerReviewResponseV1RelationshipsReview struct {
	Links *AppAvailabilityRelationshipsAppLinks            `json:"links,omitempty"`
	Data  *CustomerReviewResponseV1RelationshipsReviewData `json:"data,omitempty"`
}

// NewCustomerReviewResponseV1RelationshipsReview instantiates a new CustomerReviewResponseV1RelationshipsReview object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewCustomerReviewResponseV1RelationshipsReview() *CustomerReviewResponseV1RelationshipsReview {
	this := CustomerReviewResponseV1RelationshipsReview{}
	return &this
}

// NewCustomerReviewResponseV1RelationshipsReviewWithDefaults instantiates a new CustomerReviewResponseV1RelationshipsReview object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewCustomerReviewResponseV1RelationshipsReviewWithDefaults() *CustomerReviewResponseV1RelationshipsReview {
	this := CustomerReviewResponseV1RelationshipsReview{}
	return &this
}

// GetLinks returns the Links field value if set, zero value otherwise.
func (o *CustomerReviewResponseV1RelationshipsReview) GetLinks() AppAvailabilityRelationshipsAppLinks {
	if o == nil || IsNil(o.Links) {
		var ret AppAvailabilityRelationshipsAppLinks
		return ret
	}
	return *o.Links
}

// GetLinksOk returns a tuple with the Links field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustomerReviewResponseV1RelationshipsReview) GetLinksOk() (*AppAvailabilityRelationshipsAppLinks, bool) {
	if o == nil || IsNil(o.Links) {
		return nil, false
	}
	return o.Links, true
}

// HasLinks returns a boolean if a field has been set.
func (o *CustomerReviewResponseV1RelationshipsReview) HasLinks() bool {
	if o != nil && !IsNil(o.Links) {
		return true
	}

	return false
}

// SetLinks gets a reference to the given AppAvailabilityRelationshipsAppLinks and assigns it to the Links field.
func (o *CustomerReviewResponseV1RelationshipsReview) SetLinks(v AppAvailabilityRelationshipsAppLinks) {
	o.Links = &v
}

// GetData returns the Data field value if set, zero value otherwise.
func (o *CustomerReviewResponseV1RelationshipsReview) GetData() CustomerReviewResponseV1RelationshipsReviewData {
	if o == nil || IsNil(o.Data) {
		var ret CustomerReviewResponseV1RelationshipsReviewData
		return ret
	}
	return *o.Data
}

// GetDataOk returns a tuple with the Data field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustomerReviewResponseV1RelationshipsReview) GetDataOk() (*CustomerReviewResponseV1RelationshipsReviewData, bool) {
	if o == nil || IsNil(o.Data) {
		return nil, false
	}
	return o.Data, true
}

// HasData returns a boolean if a field has been set.
func (o *CustomerReviewResponseV1RelationshipsReview) HasData() bool {
	if o != nil && !IsNil(o.Data) {
		return true
	}

	return false
}

// SetData gets a reference to the given CustomerReviewResponseV1RelationshipsReviewData and assigns it to the Data field.
func (o *CustomerReviewResponseV1RelationshipsReview) SetData(v CustomerReviewResponseV1RelationshipsReviewData) {
	o.Data = &v
}

func (o CustomerReviewResponseV1RelationshipsReview) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o CustomerReviewResponseV1RelationshipsReview) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.Links) {
		toSerialize["links"] = o.Links
	}
	if !IsNil(o.Data) {
		toSerialize["data"] = o.Data
	}
	return toSerialize, nil
}

type NullableCustomerReviewResponseV1RelationshipsReview struct {
	value *CustomerReviewResponseV1RelationshipsReview
	isSet bool
}

func (v NullableCustomerReviewResponseV1RelationshipsReview) Get() *CustomerReviewResponseV1RelationshipsReview {
	return v.value
}

func (v *NullableCustomerReviewResponseV1RelationshipsReview) Set(val *CustomerReviewResponseV1RelationshipsReview) {
	v.value = val
	v.isSet = true
}

func (v NullableCustomerReviewResponseV1RelationshipsReview) IsSet() bool {
	return v.isSet
}

func (v *NullableCustomerReviewResponseV1RelationshipsReview) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableCustomerReviewResponseV1RelationshipsReview(val *CustomerReviewResponseV1RelationshipsReview) *NullableCustomerReviewResponseV1RelationshipsReview {
	return &NullableCustomerReviewResponseV1RelationshipsReview{value: val, isSet: true}
}

func (v NullableCustomerReviewResponseV1RelationshipsReview) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableCustomerReviewResponseV1RelationshipsReview) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
