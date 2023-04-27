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

// checks if the UserInvitationResponse type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &UserInvitationResponse{}

// UserInvitationResponse struct for UserInvitationResponse
type UserInvitationResponse struct {
	Data     UserInvitation `json:"data"`
	Included []App          `json:"included,omitempty"`
	Links    DocumentLinks  `json:"links"`
}

// NewUserInvitationResponse instantiates a new UserInvitationResponse object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewUserInvitationResponse(data UserInvitation, links DocumentLinks) *UserInvitationResponse {
	this := UserInvitationResponse{}
	this.Data = data
	this.Links = links
	return &this
}

// NewUserInvitationResponseWithDefaults instantiates a new UserInvitationResponse object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewUserInvitationResponseWithDefaults() *UserInvitationResponse {
	this := UserInvitationResponse{}
	return &this
}

// GetData returns the Data field value
func (o *UserInvitationResponse) GetData() UserInvitation {
	if o == nil {
		var ret UserInvitation
		return ret
	}

	return o.Data
}

// GetDataOk returns a tuple with the Data field value
// and a boolean to check if the value has been set.
func (o *UserInvitationResponse) GetDataOk() (*UserInvitation, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Data, true
}

// SetData sets field value
func (o *UserInvitationResponse) SetData(v UserInvitation) {
	o.Data = v
}

// GetIncluded returns the Included field value if set, zero value otherwise.
func (o *UserInvitationResponse) GetIncluded() []App {
	if o == nil || IsNil(o.Included) {
		var ret []App
		return ret
	}
	return o.Included
}

// GetIncludedOk returns a tuple with the Included field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *UserInvitationResponse) GetIncludedOk() ([]App, bool) {
	if o == nil || IsNil(o.Included) {
		return nil, false
	}
	return o.Included, true
}

// HasIncluded returns a boolean if a field has been set.
func (o *UserInvitationResponse) HasIncluded() bool {
	if o != nil && !IsNil(o.Included) {
		return true
	}

	return false
}

// SetIncluded gets a reference to the given []App and assigns it to the Included field.
func (o *UserInvitationResponse) SetIncluded(v []App) {
	o.Included = v
}

// GetLinks returns the Links field value
func (o *UserInvitationResponse) GetLinks() DocumentLinks {
	if o == nil {
		var ret DocumentLinks
		return ret
	}

	return o.Links
}

// GetLinksOk returns a tuple with the Links field value
// and a boolean to check if the value has been set.
func (o *UserInvitationResponse) GetLinksOk() (*DocumentLinks, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Links, true
}

// SetLinks sets field value
func (o *UserInvitationResponse) SetLinks(v DocumentLinks) {
	o.Links = v
}

func (o UserInvitationResponse) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o UserInvitationResponse) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["data"] = o.Data
	if !IsNil(o.Included) {
		toSerialize["included"] = o.Included
	}
	toSerialize["links"] = o.Links
	return toSerialize, nil
}

type NullableUserInvitationResponse struct {
	value *UserInvitationResponse
	isSet bool
}

func (v NullableUserInvitationResponse) Get() *UserInvitationResponse {
	return v.value
}

func (v *NullableUserInvitationResponse) Set(val *UserInvitationResponse) {
	v.value = val
	v.isSet = true
}

func (v NullableUserInvitationResponse) IsSet() bool {
	return v.isSet
}

func (v *NullableUserInvitationResponse) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableUserInvitationResponse(val *UserInvitationResponse) *NullableUserInvitationResponse {
	return &NullableUserInvitationResponse{value: val, isSet: true}
}

func (v NullableUserInvitationResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableUserInvitationResponse) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
