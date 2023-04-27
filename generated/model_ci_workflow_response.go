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

// checks if the CiWorkflowResponse type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &CiWorkflowResponse{}

// CiWorkflowResponse struct for CiWorkflowResponse
type CiWorkflowResponse struct {
	Data     CiWorkflow                         `json:"data"`
	Included []CiWorkflowsResponseIncludedInner `json:"included,omitempty"`
	Links    DocumentLinks                      `json:"links"`
}

// NewCiWorkflowResponse instantiates a new CiWorkflowResponse object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewCiWorkflowResponse(data CiWorkflow, links DocumentLinks) *CiWorkflowResponse {
	this := CiWorkflowResponse{}
	this.Data = data
	this.Links = links
	return &this
}

// NewCiWorkflowResponseWithDefaults instantiates a new CiWorkflowResponse object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewCiWorkflowResponseWithDefaults() *CiWorkflowResponse {
	this := CiWorkflowResponse{}
	return &this
}

// GetData returns the Data field value
func (o *CiWorkflowResponse) GetData() CiWorkflow {
	if o == nil {
		var ret CiWorkflow
		return ret
	}

	return o.Data
}

// GetDataOk returns a tuple with the Data field value
// and a boolean to check if the value has been set.
func (o *CiWorkflowResponse) GetDataOk() (*CiWorkflow, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Data, true
}

// SetData sets field value
func (o *CiWorkflowResponse) SetData(v CiWorkflow) {
	o.Data = v
}

// GetIncluded returns the Included field value if set, zero value otherwise.
func (o *CiWorkflowResponse) GetIncluded() []CiWorkflowsResponseIncludedInner {
	if o == nil || IsNil(o.Included) {
		var ret []CiWorkflowsResponseIncludedInner
		return ret
	}
	return o.Included
}

// GetIncludedOk returns a tuple with the Included field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CiWorkflowResponse) GetIncludedOk() ([]CiWorkflowsResponseIncludedInner, bool) {
	if o == nil || IsNil(o.Included) {
		return nil, false
	}
	return o.Included, true
}

// HasIncluded returns a boolean if a field has been set.
func (o *CiWorkflowResponse) HasIncluded() bool {
	if o != nil && !IsNil(o.Included) {
		return true
	}

	return false
}

// SetIncluded gets a reference to the given []CiWorkflowsResponseIncludedInner and assigns it to the Included field.
func (o *CiWorkflowResponse) SetIncluded(v []CiWorkflowsResponseIncludedInner) {
	o.Included = v
}

// GetLinks returns the Links field value
func (o *CiWorkflowResponse) GetLinks() DocumentLinks {
	if o == nil {
		var ret DocumentLinks
		return ret
	}

	return o.Links
}

// GetLinksOk returns a tuple with the Links field value
// and a boolean to check if the value has been set.
func (o *CiWorkflowResponse) GetLinksOk() (*DocumentLinks, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Links, true
}

// SetLinks sets field value
func (o *CiWorkflowResponse) SetLinks(v DocumentLinks) {
	o.Links = v
}

func (o CiWorkflowResponse) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o CiWorkflowResponse) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["data"] = o.Data
	if !IsNil(o.Included) {
		toSerialize["included"] = o.Included
	}
	toSerialize["links"] = o.Links
	return toSerialize, nil
}

type NullableCiWorkflowResponse struct {
	value *CiWorkflowResponse
	isSet bool
}

func (v NullableCiWorkflowResponse) Get() *CiWorkflowResponse {
	return v.value
}

func (v *NullableCiWorkflowResponse) Set(val *CiWorkflowResponse) {
	v.value = val
	v.isSet = true
}

func (v NullableCiWorkflowResponse) IsSet() bool {
	return v.isSet
}

func (v *NullableCiWorkflowResponse) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableCiWorkflowResponse(val *CiWorkflowResponse) *NullableCiWorkflowResponse {
	return &NullableCiWorkflowResponse{value: val, isSet: true}
}

func (v NullableCiWorkflowResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableCiWorkflowResponse) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
