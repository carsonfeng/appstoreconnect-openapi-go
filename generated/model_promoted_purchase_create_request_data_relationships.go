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

// checks if the PromotedPurchaseCreateRequestDataRelationships type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &PromotedPurchaseCreateRequestDataRelationships{}

// PromotedPurchaseCreateRequestDataRelationships struct for PromotedPurchaseCreateRequestDataRelationships
type PromotedPurchaseCreateRequestDataRelationships struct {
	App             AppAvailabilityCreateRequestDataRelationshipsApp            `json:"app"`
	InAppPurchaseV2 *InAppPurchasePriceInlineCreateRelationshipsInAppPurchaseV2 `json:"inAppPurchaseV2,omitempty"`
	Subscription    *PromotedPurchaseCreateRequestDataRelationshipsSubscription `json:"subscription,omitempty"`
}

// NewPromotedPurchaseCreateRequestDataRelationships instantiates a new PromotedPurchaseCreateRequestDataRelationships object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewPromotedPurchaseCreateRequestDataRelationships(app AppAvailabilityCreateRequestDataRelationshipsApp) *PromotedPurchaseCreateRequestDataRelationships {
	this := PromotedPurchaseCreateRequestDataRelationships{}
	this.App = app
	return &this
}

// NewPromotedPurchaseCreateRequestDataRelationshipsWithDefaults instantiates a new PromotedPurchaseCreateRequestDataRelationships object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewPromotedPurchaseCreateRequestDataRelationshipsWithDefaults() *PromotedPurchaseCreateRequestDataRelationships {
	this := PromotedPurchaseCreateRequestDataRelationships{}
	return &this
}

// GetApp returns the App field value
func (o *PromotedPurchaseCreateRequestDataRelationships) GetApp() AppAvailabilityCreateRequestDataRelationshipsApp {
	if o == nil {
		var ret AppAvailabilityCreateRequestDataRelationshipsApp
		return ret
	}

	return o.App
}

// GetAppOk returns a tuple with the App field value
// and a boolean to check if the value has been set.
func (o *PromotedPurchaseCreateRequestDataRelationships) GetAppOk() (*AppAvailabilityCreateRequestDataRelationshipsApp, bool) {
	if o == nil {
		return nil, false
	}
	return &o.App, true
}

// SetApp sets field value
func (o *PromotedPurchaseCreateRequestDataRelationships) SetApp(v AppAvailabilityCreateRequestDataRelationshipsApp) {
	o.App = v
}

// GetInAppPurchaseV2 returns the InAppPurchaseV2 field value if set, zero value otherwise.
func (o *PromotedPurchaseCreateRequestDataRelationships) GetInAppPurchaseV2() InAppPurchasePriceInlineCreateRelationshipsInAppPurchaseV2 {
	if o == nil || IsNil(o.InAppPurchaseV2) {
		var ret InAppPurchasePriceInlineCreateRelationshipsInAppPurchaseV2
		return ret
	}
	return *o.InAppPurchaseV2
}

// GetInAppPurchaseV2Ok returns a tuple with the InAppPurchaseV2 field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *PromotedPurchaseCreateRequestDataRelationships) GetInAppPurchaseV2Ok() (*InAppPurchasePriceInlineCreateRelationshipsInAppPurchaseV2, bool) {
	if o == nil || IsNil(o.InAppPurchaseV2) {
		return nil, false
	}
	return o.InAppPurchaseV2, true
}

// HasInAppPurchaseV2 returns a boolean if a field has been set.
func (o *PromotedPurchaseCreateRequestDataRelationships) HasInAppPurchaseV2() bool {
	if o != nil && !IsNil(o.InAppPurchaseV2) {
		return true
	}

	return false
}

// SetInAppPurchaseV2 gets a reference to the given InAppPurchasePriceInlineCreateRelationshipsInAppPurchaseV2 and assigns it to the InAppPurchaseV2 field.
func (o *PromotedPurchaseCreateRequestDataRelationships) SetInAppPurchaseV2(v InAppPurchasePriceInlineCreateRelationshipsInAppPurchaseV2) {
	o.InAppPurchaseV2 = &v
}

// GetSubscription returns the Subscription field value if set, zero value otherwise.
func (o *PromotedPurchaseCreateRequestDataRelationships) GetSubscription() PromotedPurchaseCreateRequestDataRelationshipsSubscription {
	if o == nil || IsNil(o.Subscription) {
		var ret PromotedPurchaseCreateRequestDataRelationshipsSubscription
		return ret
	}
	return *o.Subscription
}

// GetSubscriptionOk returns a tuple with the Subscription field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *PromotedPurchaseCreateRequestDataRelationships) GetSubscriptionOk() (*PromotedPurchaseCreateRequestDataRelationshipsSubscription, bool) {
	if o == nil || IsNil(o.Subscription) {
		return nil, false
	}
	return o.Subscription, true
}

// HasSubscription returns a boolean if a field has been set.
func (o *PromotedPurchaseCreateRequestDataRelationships) HasSubscription() bool {
	if o != nil && !IsNil(o.Subscription) {
		return true
	}

	return false
}

// SetSubscription gets a reference to the given PromotedPurchaseCreateRequestDataRelationshipsSubscription and assigns it to the Subscription field.
func (o *PromotedPurchaseCreateRequestDataRelationships) SetSubscription(v PromotedPurchaseCreateRequestDataRelationshipsSubscription) {
	o.Subscription = &v
}

func (o PromotedPurchaseCreateRequestDataRelationships) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o PromotedPurchaseCreateRequestDataRelationships) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["app"] = o.App
	if !IsNil(o.InAppPurchaseV2) {
		toSerialize["inAppPurchaseV2"] = o.InAppPurchaseV2
	}
	if !IsNil(o.Subscription) {
		toSerialize["subscription"] = o.Subscription
	}
	return toSerialize, nil
}

type NullablePromotedPurchaseCreateRequestDataRelationships struct {
	value *PromotedPurchaseCreateRequestDataRelationships
	isSet bool
}

func (v NullablePromotedPurchaseCreateRequestDataRelationships) Get() *PromotedPurchaseCreateRequestDataRelationships {
	return v.value
}

func (v *NullablePromotedPurchaseCreateRequestDataRelationships) Set(val *PromotedPurchaseCreateRequestDataRelationships) {
	v.value = val
	v.isSet = true
}

func (v NullablePromotedPurchaseCreateRequestDataRelationships) IsSet() bool {
	return v.isSet
}

func (v *NullablePromotedPurchaseCreateRequestDataRelationships) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullablePromotedPurchaseCreateRequestDataRelationships(val *PromotedPurchaseCreateRequestDataRelationships) *NullablePromotedPurchaseCreateRequestDataRelationships {
	return &NullablePromotedPurchaseCreateRequestDataRelationships{value: val, isSet: true}
}

func (v NullablePromotedPurchaseCreateRequestDataRelationships) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullablePromotedPurchaseCreateRequestDataRelationships) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
