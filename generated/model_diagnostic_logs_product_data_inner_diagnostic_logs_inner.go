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

// checks if the DiagnosticLogsProductDataInnerDiagnosticLogsInner type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &DiagnosticLogsProductDataInnerDiagnosticLogsInner{}

// DiagnosticLogsProductDataInnerDiagnosticLogsInner struct for DiagnosticLogsProductDataInnerDiagnosticLogsInner
type DiagnosticLogsProductDataInnerDiagnosticLogsInner struct {
	CallStackTree      []DiagnosticLogsProductDataInnerDiagnosticLogsInnerCallStackTreeInner `json:"callStackTree,omitempty"`
	DiagnosticMetaData *DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData  `json:"diagnosticMetaData,omitempty"`
}

// NewDiagnosticLogsProductDataInnerDiagnosticLogsInner instantiates a new DiagnosticLogsProductDataInnerDiagnosticLogsInner object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewDiagnosticLogsProductDataInnerDiagnosticLogsInner() *DiagnosticLogsProductDataInnerDiagnosticLogsInner {
	this := DiagnosticLogsProductDataInnerDiagnosticLogsInner{}
	return &this
}

// NewDiagnosticLogsProductDataInnerDiagnosticLogsInnerWithDefaults instantiates a new DiagnosticLogsProductDataInnerDiagnosticLogsInner object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewDiagnosticLogsProductDataInnerDiagnosticLogsInnerWithDefaults() *DiagnosticLogsProductDataInnerDiagnosticLogsInner {
	this := DiagnosticLogsProductDataInnerDiagnosticLogsInner{}
	return &this
}

// GetCallStackTree returns the CallStackTree field value if set, zero value otherwise.
func (o *DiagnosticLogsProductDataInnerDiagnosticLogsInner) GetCallStackTree() []DiagnosticLogsProductDataInnerDiagnosticLogsInnerCallStackTreeInner {
	if o == nil || IsNil(o.CallStackTree) {
		var ret []DiagnosticLogsProductDataInnerDiagnosticLogsInnerCallStackTreeInner
		return ret
	}
	return o.CallStackTree
}

// GetCallStackTreeOk returns a tuple with the CallStackTree field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DiagnosticLogsProductDataInnerDiagnosticLogsInner) GetCallStackTreeOk() ([]DiagnosticLogsProductDataInnerDiagnosticLogsInnerCallStackTreeInner, bool) {
	if o == nil || IsNil(o.CallStackTree) {
		return nil, false
	}
	return o.CallStackTree, true
}

// HasCallStackTree returns a boolean if a field has been set.
func (o *DiagnosticLogsProductDataInnerDiagnosticLogsInner) HasCallStackTree() bool {
	if o != nil && !IsNil(o.CallStackTree) {
		return true
	}

	return false
}

// SetCallStackTree gets a reference to the given []DiagnosticLogsProductDataInnerDiagnosticLogsInnerCallStackTreeInner and assigns it to the CallStackTree field.
func (o *DiagnosticLogsProductDataInnerDiagnosticLogsInner) SetCallStackTree(v []DiagnosticLogsProductDataInnerDiagnosticLogsInnerCallStackTreeInner) {
	o.CallStackTree = v
}

// GetDiagnosticMetaData returns the DiagnosticMetaData field value if set, zero value otherwise.
func (o *DiagnosticLogsProductDataInnerDiagnosticLogsInner) GetDiagnosticMetaData() DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData {
	if o == nil || IsNil(o.DiagnosticMetaData) {
		var ret DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData
		return ret
	}
	return *o.DiagnosticMetaData
}

// GetDiagnosticMetaDataOk returns a tuple with the DiagnosticMetaData field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DiagnosticLogsProductDataInnerDiagnosticLogsInner) GetDiagnosticMetaDataOk() (*DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData, bool) {
	if o == nil || IsNil(o.DiagnosticMetaData) {
		return nil, false
	}
	return o.DiagnosticMetaData, true
}

// HasDiagnosticMetaData returns a boolean if a field has been set.
func (o *DiagnosticLogsProductDataInnerDiagnosticLogsInner) HasDiagnosticMetaData() bool {
	if o != nil && !IsNil(o.DiagnosticMetaData) {
		return true
	}

	return false
}

// SetDiagnosticMetaData gets a reference to the given DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData and assigns it to the DiagnosticMetaData field.
func (o *DiagnosticLogsProductDataInnerDiagnosticLogsInner) SetDiagnosticMetaData(v DiagnosticLogsProductDataInnerDiagnosticLogsInnerDiagnosticMetaData) {
	o.DiagnosticMetaData = &v
}

func (o DiagnosticLogsProductDataInnerDiagnosticLogsInner) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o DiagnosticLogsProductDataInnerDiagnosticLogsInner) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.CallStackTree) {
		toSerialize["callStackTree"] = o.CallStackTree
	}
	if !IsNil(o.DiagnosticMetaData) {
		toSerialize["diagnosticMetaData"] = o.DiagnosticMetaData
	}
	return toSerialize, nil
}

type NullableDiagnosticLogsProductDataInnerDiagnosticLogsInner struct {
	value *DiagnosticLogsProductDataInnerDiagnosticLogsInner
	isSet bool
}

func (v NullableDiagnosticLogsProductDataInnerDiagnosticLogsInner) Get() *DiagnosticLogsProductDataInnerDiagnosticLogsInner {
	return v.value
}

func (v *NullableDiagnosticLogsProductDataInnerDiagnosticLogsInner) Set(val *DiagnosticLogsProductDataInnerDiagnosticLogsInner) {
	v.value = val
	v.isSet = true
}

func (v NullableDiagnosticLogsProductDataInnerDiagnosticLogsInner) IsSet() bool {
	return v.isSet
}

func (v *NullableDiagnosticLogsProductDataInnerDiagnosticLogsInner) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableDiagnosticLogsProductDataInnerDiagnosticLogsInner(val *DiagnosticLogsProductDataInnerDiagnosticLogsInner) *NullableDiagnosticLogsProductDataInnerDiagnosticLogsInner {
	return &NullableDiagnosticLogsProductDataInnerDiagnosticLogsInner{value: val, isSet: true}
}

func (v NullableDiagnosticLogsProductDataInnerDiagnosticLogsInner) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableDiagnosticLogsProductDataInnerDiagnosticLogsInner) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
