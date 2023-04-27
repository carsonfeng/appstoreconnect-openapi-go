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

// checks if the EndUserLicenseAgreementRelationships type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &EndUserLicenseAgreementRelationships{}

// EndUserLicenseAgreementRelationships struct for EndUserLicenseAgreementRelationships
type EndUserLicenseAgreementRelationships struct {
	App         *AppAvailabilityRelationshipsApp                  `json:"app,omitempty"`
	Territories *AppAvailabilityRelationshipsAvailableTerritories `json:"territories,omitempty"`
}

// NewEndUserLicenseAgreementRelationships instantiates a new EndUserLicenseAgreementRelationships object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewEndUserLicenseAgreementRelationships() *EndUserLicenseAgreementRelationships {
	this := EndUserLicenseAgreementRelationships{}
	return &this
}

// NewEndUserLicenseAgreementRelationshipsWithDefaults instantiates a new EndUserLicenseAgreementRelationships object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewEndUserLicenseAgreementRelationshipsWithDefaults() *EndUserLicenseAgreementRelationships {
	this := EndUserLicenseAgreementRelationships{}
	return &this
}

// GetApp returns the App field value if set, zero value otherwise.
func (o *EndUserLicenseAgreementRelationships) GetApp() AppAvailabilityRelationshipsApp {
	if o == nil || IsNil(o.App) {
		var ret AppAvailabilityRelationshipsApp
		return ret
	}
	return *o.App
}

// GetAppOk returns a tuple with the App field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *EndUserLicenseAgreementRelationships) GetAppOk() (*AppAvailabilityRelationshipsApp, bool) {
	if o == nil || IsNil(o.App) {
		return nil, false
	}
	return o.App, true
}

// HasApp returns a boolean if a field has been set.
func (o *EndUserLicenseAgreementRelationships) HasApp() bool {
	if o != nil && !IsNil(o.App) {
		return true
	}

	return false
}

// SetApp gets a reference to the given AppAvailabilityRelationshipsApp and assigns it to the App field.
func (o *EndUserLicenseAgreementRelationships) SetApp(v AppAvailabilityRelationshipsApp) {
	o.App = &v
}

// GetTerritories returns the Territories field value if set, zero value otherwise.
func (o *EndUserLicenseAgreementRelationships) GetTerritories() AppAvailabilityRelationshipsAvailableTerritories {
	if o == nil || IsNil(o.Territories) {
		var ret AppAvailabilityRelationshipsAvailableTerritories
		return ret
	}
	return *o.Territories
}

// GetTerritoriesOk returns a tuple with the Territories field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *EndUserLicenseAgreementRelationships) GetTerritoriesOk() (*AppAvailabilityRelationshipsAvailableTerritories, bool) {
	if o == nil || IsNil(o.Territories) {
		return nil, false
	}
	return o.Territories, true
}

// HasTerritories returns a boolean if a field has been set.
func (o *EndUserLicenseAgreementRelationships) HasTerritories() bool {
	if o != nil && !IsNil(o.Territories) {
		return true
	}

	return false
}

// SetTerritories gets a reference to the given AppAvailabilityRelationshipsAvailableTerritories and assigns it to the Territories field.
func (o *EndUserLicenseAgreementRelationships) SetTerritories(v AppAvailabilityRelationshipsAvailableTerritories) {
	o.Territories = &v
}

func (o EndUserLicenseAgreementRelationships) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o EndUserLicenseAgreementRelationships) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.App) {
		toSerialize["app"] = o.App
	}
	if !IsNil(o.Territories) {
		toSerialize["territories"] = o.Territories
	}
	return toSerialize, nil
}

type NullableEndUserLicenseAgreementRelationships struct {
	value *EndUserLicenseAgreementRelationships
	isSet bool
}

func (v NullableEndUserLicenseAgreementRelationships) Get() *EndUserLicenseAgreementRelationships {
	return v.value
}

func (v *NullableEndUserLicenseAgreementRelationships) Set(val *EndUserLicenseAgreementRelationships) {
	v.value = val
	v.isSet = true
}

func (v NullableEndUserLicenseAgreementRelationships) IsSet() bool {
	return v.isSet
}

func (v *NullableEndUserLicenseAgreementRelationships) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableEndUserLicenseAgreementRelationships(val *EndUserLicenseAgreementRelationships) *NullableEndUserLicenseAgreementRelationships {
	return &NullableEndUserLicenseAgreementRelationships{value: val, isSet: true}
}

func (v NullableEndUserLicenseAgreementRelationships) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableEndUserLicenseAgreementRelationships) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
