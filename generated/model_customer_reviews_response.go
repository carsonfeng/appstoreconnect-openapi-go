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

// checks if the CustomerReviewsResponse type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &CustomerReviewsResponse{}

// CustomerReviewsResponse struct for CustomerReviewsResponse
type CustomerReviewsResponse struct {
	Data     []CustomerReview           `json:"data"`
	Included []CustomerReviewResponseV1 `json:"included,omitempty"`
	Links    PagedDocumentLinks         `json:"links"`
	Meta     *PagingInformation         `json:"meta,omitempty"`
}

// NewCustomerReviewsResponse instantiates a new CustomerReviewsResponse object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewCustomerReviewsResponse(data []CustomerReview, links PagedDocumentLinks) *CustomerReviewsResponse {
	this := CustomerReviewsResponse{}
	this.Data = data
	this.Links = links
	return &this
}

// NewCustomerReviewsResponseWithDefaults instantiates a new CustomerReviewsResponse object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewCustomerReviewsResponseWithDefaults() *CustomerReviewsResponse {
	this := CustomerReviewsResponse{}
	return &this
}

// GetData returns the Data field value
func (o *CustomerReviewsResponse) GetData() []CustomerReview {
	if o == nil {
		var ret []CustomerReview
		return ret
	}

	return o.Data
}

// GetDataOk returns a tuple with the Data field value
// and a boolean to check if the value has been set.
func (o *CustomerReviewsResponse) GetDataOk() ([]CustomerReview, bool) {
	if o == nil {
		return nil, false
	}
	return o.Data, true
}

// SetData sets field value
func (o *CustomerReviewsResponse) SetData(v []CustomerReview) {
	o.Data = v
}

// GetIncluded returns the Included field value if set, zero value otherwise.
func (o *CustomerReviewsResponse) GetIncluded() []CustomerReviewResponseV1 {
	if o == nil || IsNil(o.Included) {
		var ret []CustomerReviewResponseV1
		return ret
	}
	return o.Included
}

// GetIncludedOk returns a tuple with the Included field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustomerReviewsResponse) GetIncludedOk() ([]CustomerReviewResponseV1, bool) {
	if o == nil || IsNil(o.Included) {
		return nil, false
	}
	return o.Included, true
}

// HasIncluded returns a boolean if a field has been set.
func (o *CustomerReviewsResponse) HasIncluded() bool {
	if o != nil && !IsNil(o.Included) {
		return true
	}

	return false
}

// SetIncluded gets a reference to the given []CustomerReviewResponseV1 and assigns it to the Included field.
func (o *CustomerReviewsResponse) SetIncluded(v []CustomerReviewResponseV1) {
	o.Included = v
}

// GetLinks returns the Links field value
func (o *CustomerReviewsResponse) GetLinks() PagedDocumentLinks {
	if o == nil {
		var ret PagedDocumentLinks
		return ret
	}

	return o.Links
}

// GetLinksOk returns a tuple with the Links field value
// and a boolean to check if the value has been set.
func (o *CustomerReviewsResponse) GetLinksOk() (*PagedDocumentLinks, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Links, true
}

// SetLinks sets field value
func (o *CustomerReviewsResponse) SetLinks(v PagedDocumentLinks) {
	o.Links = v
}

// GetMeta returns the Meta field value if set, zero value otherwise.
func (o *CustomerReviewsResponse) GetMeta() PagingInformation {
	if o == nil || IsNil(o.Meta) {
		var ret PagingInformation
		return ret
	}
	return *o.Meta
}

// GetMetaOk returns a tuple with the Meta field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustomerReviewsResponse) GetMetaOk() (*PagingInformation, bool) {
	if o == nil || IsNil(o.Meta) {
		return nil, false
	}
	return o.Meta, true
}

// HasMeta returns a boolean if a field has been set.
func (o *CustomerReviewsResponse) HasMeta() bool {
	if o != nil && !IsNil(o.Meta) {
		return true
	}

	return false
}

// SetMeta gets a reference to the given PagingInformation and assigns it to the Meta field.
func (o *CustomerReviewsResponse) SetMeta(v PagingInformation) {
	o.Meta = &v
}

func (o CustomerReviewsResponse) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o CustomerReviewsResponse) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["data"] = o.Data
	if !IsNil(o.Included) {
		toSerialize["included"] = o.Included
	}
	toSerialize["links"] = o.Links
	if !IsNil(o.Meta) {
		toSerialize["meta"] = o.Meta
	}
	return toSerialize, nil
}

type NullableCustomerReviewsResponse struct {
	value *CustomerReviewsResponse
	isSet bool
}

func (v NullableCustomerReviewsResponse) Get() *CustomerReviewsResponse {
	return v.value
}

func (v *NullableCustomerReviewsResponse) Set(val *CustomerReviewsResponse) {
	v.value = val
	v.isSet = true
}

func (v NullableCustomerReviewsResponse) IsSet() bool {
	return v.isSet
}

func (v *NullableCustomerReviewsResponse) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableCustomerReviewsResponse(val *CustomerReviewsResponse) *NullableCustomerReviewsResponse {
	return &NullableCustomerReviewsResponse{value: val, isSet: true}
}

func (v NullableCustomerReviewsResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableCustomerReviewsResponse) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
