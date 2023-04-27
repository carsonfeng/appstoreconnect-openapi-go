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

// checks if the ErrorResponseErrorsInner type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &ErrorResponseErrorsInner{}

// ErrorResponseErrorsInner struct for ErrorResponseErrorsInner
type ErrorResponseErrorsInner struct {
	Id     *string                         `json:"id,omitempty"`
	Status string                          `json:"status"`
	Code   string                          `json:"code"`
	Title  string                          `json:"title"`
	Detail string                          `json:"detail"`
	Source *ErrorResponseErrorsInnerSource `json:"source,omitempty"`
}

// NewErrorResponseErrorsInner instantiates a new ErrorResponseErrorsInner object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewErrorResponseErrorsInner(status string, code string, title string, detail string) *ErrorResponseErrorsInner {
	this := ErrorResponseErrorsInner{}
	this.Status = status
	this.Code = code
	this.Title = title
	this.Detail = detail
	return &this
}

// NewErrorResponseErrorsInnerWithDefaults instantiates a new ErrorResponseErrorsInner object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewErrorResponseErrorsInnerWithDefaults() *ErrorResponseErrorsInner {
	this := ErrorResponseErrorsInner{}
	return &this
}

// GetId returns the Id field value if set, zero value otherwise.
func (o *ErrorResponseErrorsInner) GetId() string {
	if o == nil || IsNil(o.Id) {
		var ret string
		return ret
	}
	return *o.Id
}

// GetIdOk returns a tuple with the Id field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ErrorResponseErrorsInner) GetIdOk() (*string, bool) {
	if o == nil || IsNil(o.Id) {
		return nil, false
	}
	return o.Id, true
}

// HasId returns a boolean if a field has been set.
func (o *ErrorResponseErrorsInner) HasId() bool {
	if o != nil && !IsNil(o.Id) {
		return true
	}

	return false
}

// SetId gets a reference to the given string and assigns it to the Id field.
func (o *ErrorResponseErrorsInner) SetId(v string) {
	o.Id = &v
}

// GetStatus returns the Status field value
func (o *ErrorResponseErrorsInner) GetStatus() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Status
}

// GetStatusOk returns a tuple with the Status field value
// and a boolean to check if the value has been set.
func (o *ErrorResponseErrorsInner) GetStatusOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Status, true
}

// SetStatus sets field value
func (o *ErrorResponseErrorsInner) SetStatus(v string) {
	o.Status = v
}

// GetCode returns the Code field value
func (o *ErrorResponseErrorsInner) GetCode() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Code
}

// GetCodeOk returns a tuple with the Code field value
// and a boolean to check if the value has been set.
func (o *ErrorResponseErrorsInner) GetCodeOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Code, true
}

// SetCode sets field value
func (o *ErrorResponseErrorsInner) SetCode(v string) {
	o.Code = v
}

// GetTitle returns the Title field value
func (o *ErrorResponseErrorsInner) GetTitle() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Title
}

// GetTitleOk returns a tuple with the Title field value
// and a boolean to check if the value has been set.
func (o *ErrorResponseErrorsInner) GetTitleOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Title, true
}

// SetTitle sets field value
func (o *ErrorResponseErrorsInner) SetTitle(v string) {
	o.Title = v
}

// GetDetail returns the Detail field value
func (o *ErrorResponseErrorsInner) GetDetail() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Detail
}

// GetDetailOk returns a tuple with the Detail field value
// and a boolean to check if the value has been set.
func (o *ErrorResponseErrorsInner) GetDetailOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Detail, true
}

// SetDetail sets field value
func (o *ErrorResponseErrorsInner) SetDetail(v string) {
	o.Detail = v
}

// GetSource returns the Source field value if set, zero value otherwise.
func (o *ErrorResponseErrorsInner) GetSource() ErrorResponseErrorsInnerSource {
	if o == nil || IsNil(o.Source) {
		var ret ErrorResponseErrorsInnerSource
		return ret
	}
	return *o.Source
}

// GetSourceOk returns a tuple with the Source field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ErrorResponseErrorsInner) GetSourceOk() (*ErrorResponseErrorsInnerSource, bool) {
	if o == nil || IsNil(o.Source) {
		return nil, false
	}
	return o.Source, true
}

// HasSource returns a boolean if a field has been set.
func (o *ErrorResponseErrorsInner) HasSource() bool {
	if o != nil && !IsNil(o.Source) {
		return true
	}

	return false
}

// SetSource gets a reference to the given ErrorResponseErrorsInnerSource and assigns it to the Source field.
func (o *ErrorResponseErrorsInner) SetSource(v ErrorResponseErrorsInnerSource) {
	o.Source = &v
}

func (o ErrorResponseErrorsInner) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o ErrorResponseErrorsInner) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.Id) {
		toSerialize["id"] = o.Id
	}
	toSerialize["status"] = o.Status
	toSerialize["code"] = o.Code
	toSerialize["title"] = o.Title
	toSerialize["detail"] = o.Detail
	if !IsNil(o.Source) {
		toSerialize["source"] = o.Source
	}
	return toSerialize, nil
}

type NullableErrorResponseErrorsInner struct {
	value *ErrorResponseErrorsInner
	isSet bool
}

func (v NullableErrorResponseErrorsInner) Get() *ErrorResponseErrorsInner {
	return v.value
}

func (v *NullableErrorResponseErrorsInner) Set(val *ErrorResponseErrorsInner) {
	v.value = val
	v.isSet = true
}

func (v NullableErrorResponseErrorsInner) IsSet() bool {
	return v.isSet
}

func (v *NullableErrorResponseErrorsInner) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableErrorResponseErrorsInner(val *ErrorResponseErrorsInner) *NullableErrorResponseErrorsInner {
	return &NullableErrorResponseErrorsInner{value: val, isSet: true}
}

func (v NullableErrorResponseErrorsInner) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableErrorResponseErrorsInner) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
