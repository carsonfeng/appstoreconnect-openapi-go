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

// checks if the DiagnosticLogs type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &DiagnosticLogs{}

// DiagnosticLogs struct for DiagnosticLogs
type DiagnosticLogs struct {
	ProductData []DiagnosticLogsProductDataInner `json:"productData,omitempty"`
	Version     *string                          `json:"version,omitempty"`
}

// NewDiagnosticLogs instantiates a new DiagnosticLogs object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewDiagnosticLogs() *DiagnosticLogs {
	this := DiagnosticLogs{}
	return &this
}

// NewDiagnosticLogsWithDefaults instantiates a new DiagnosticLogs object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewDiagnosticLogsWithDefaults() *DiagnosticLogs {
	this := DiagnosticLogs{}
	return &this
}

// GetProductData returns the ProductData field value if set, zero value otherwise.
func (o *DiagnosticLogs) GetProductData() []DiagnosticLogsProductDataInner {
	if o == nil || IsNil(o.ProductData) {
		var ret []DiagnosticLogsProductDataInner
		return ret
	}
	return o.ProductData
}

// GetProductDataOk returns a tuple with the ProductData field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DiagnosticLogs) GetProductDataOk() ([]DiagnosticLogsProductDataInner, bool) {
	if o == nil || IsNil(o.ProductData) {
		return nil, false
	}
	return o.ProductData, true
}

// HasProductData returns a boolean if a field has been set.
func (o *DiagnosticLogs) HasProductData() bool {
	if o != nil && !IsNil(o.ProductData) {
		return true
	}

	return false
}

// SetProductData gets a reference to the given []DiagnosticLogsProductDataInner and assigns it to the ProductData field.
func (o *DiagnosticLogs) SetProductData(v []DiagnosticLogsProductDataInner) {
	o.ProductData = v
}

// GetVersion returns the Version field value if set, zero value otherwise.
func (o *DiagnosticLogs) GetVersion() string {
	if o == nil || IsNil(o.Version) {
		var ret string
		return ret
	}
	return *o.Version
}

// GetVersionOk returns a tuple with the Version field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DiagnosticLogs) GetVersionOk() (*string, bool) {
	if o == nil || IsNil(o.Version) {
		return nil, false
	}
	return o.Version, true
}

// HasVersion returns a boolean if a field has been set.
func (o *DiagnosticLogs) HasVersion() bool {
	if o != nil && !IsNil(o.Version) {
		return true
	}

	return false
}

// SetVersion gets a reference to the given string and assigns it to the Version field.
func (o *DiagnosticLogs) SetVersion(v string) {
	o.Version = &v
}

func (o DiagnosticLogs) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o DiagnosticLogs) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.ProductData) {
		toSerialize["productData"] = o.ProductData
	}
	if !IsNil(o.Version) {
		toSerialize["version"] = o.Version
	}
	return toSerialize, nil
}

type NullableDiagnosticLogs struct {
	value *DiagnosticLogs
	isSet bool
}

func (v NullableDiagnosticLogs) Get() *DiagnosticLogs {
	return v.value
}

func (v *NullableDiagnosticLogs) Set(val *DiagnosticLogs) {
	v.value = val
	v.isSet = true
}

func (v NullableDiagnosticLogs) IsSet() bool {
	return v.isSet
}

func (v *NullableDiagnosticLogs) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableDiagnosticLogs(val *DiagnosticLogs) *NullableDiagnosticLogs {
	return &NullableDiagnosticLogs{value: val, isSet: true}
}

func (v NullableDiagnosticLogs) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableDiagnosticLogs) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
