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

// checks if the BetaAppLocalizationUpdateRequestDataAttributes type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &BetaAppLocalizationUpdateRequestDataAttributes{}

// BetaAppLocalizationUpdateRequestDataAttributes struct for BetaAppLocalizationUpdateRequestDataAttributes
type BetaAppLocalizationUpdateRequestDataAttributes struct {
	FeedbackEmail     *string `json:"feedbackEmail,omitempty"`
	MarketingUrl      *string `json:"marketingUrl,omitempty"`
	PrivacyPolicyUrl  *string `json:"privacyPolicyUrl,omitempty"`
	TvOsPrivacyPolicy *string `json:"tvOsPrivacyPolicy,omitempty"`
	Description       *string `json:"description,omitempty"`
}

// NewBetaAppLocalizationUpdateRequestDataAttributes instantiates a new BetaAppLocalizationUpdateRequestDataAttributes object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewBetaAppLocalizationUpdateRequestDataAttributes() *BetaAppLocalizationUpdateRequestDataAttributes {
	this := BetaAppLocalizationUpdateRequestDataAttributes{}
	return &this
}

// NewBetaAppLocalizationUpdateRequestDataAttributesWithDefaults instantiates a new BetaAppLocalizationUpdateRequestDataAttributes object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewBetaAppLocalizationUpdateRequestDataAttributesWithDefaults() *BetaAppLocalizationUpdateRequestDataAttributes {
	this := BetaAppLocalizationUpdateRequestDataAttributes{}
	return &this
}

// GetFeedbackEmail returns the FeedbackEmail field value if set, zero value otherwise.
func (o *BetaAppLocalizationUpdateRequestDataAttributes) GetFeedbackEmail() string {
	if o == nil || IsNil(o.FeedbackEmail) {
		var ret string
		return ret
	}
	return *o.FeedbackEmail
}

// GetFeedbackEmailOk returns a tuple with the FeedbackEmail field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *BetaAppLocalizationUpdateRequestDataAttributes) GetFeedbackEmailOk() (*string, bool) {
	if o == nil || IsNil(o.FeedbackEmail) {
		return nil, false
	}
	return o.FeedbackEmail, true
}

// HasFeedbackEmail returns a boolean if a field has been set.
func (o *BetaAppLocalizationUpdateRequestDataAttributes) HasFeedbackEmail() bool {
	if o != nil && !IsNil(o.FeedbackEmail) {
		return true
	}

	return false
}

// SetFeedbackEmail gets a reference to the given string and assigns it to the FeedbackEmail field.
func (o *BetaAppLocalizationUpdateRequestDataAttributes) SetFeedbackEmail(v string) {
	o.FeedbackEmail = &v
}

// GetMarketingUrl returns the MarketingUrl field value if set, zero value otherwise.
func (o *BetaAppLocalizationUpdateRequestDataAttributes) GetMarketingUrl() string {
	if o == nil || IsNil(o.MarketingUrl) {
		var ret string
		return ret
	}
	return *o.MarketingUrl
}

// GetMarketingUrlOk returns a tuple with the MarketingUrl field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *BetaAppLocalizationUpdateRequestDataAttributes) GetMarketingUrlOk() (*string, bool) {
	if o == nil || IsNil(o.MarketingUrl) {
		return nil, false
	}
	return o.MarketingUrl, true
}

// HasMarketingUrl returns a boolean if a field has been set.
func (o *BetaAppLocalizationUpdateRequestDataAttributes) HasMarketingUrl() bool {
	if o != nil && !IsNil(o.MarketingUrl) {
		return true
	}

	return false
}

// SetMarketingUrl gets a reference to the given string and assigns it to the MarketingUrl field.
func (o *BetaAppLocalizationUpdateRequestDataAttributes) SetMarketingUrl(v string) {
	o.MarketingUrl = &v
}

// GetPrivacyPolicyUrl returns the PrivacyPolicyUrl field value if set, zero value otherwise.
func (o *BetaAppLocalizationUpdateRequestDataAttributes) GetPrivacyPolicyUrl() string {
	if o == nil || IsNil(o.PrivacyPolicyUrl) {
		var ret string
		return ret
	}
	return *o.PrivacyPolicyUrl
}

// GetPrivacyPolicyUrlOk returns a tuple with the PrivacyPolicyUrl field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *BetaAppLocalizationUpdateRequestDataAttributes) GetPrivacyPolicyUrlOk() (*string, bool) {
	if o == nil || IsNil(o.PrivacyPolicyUrl) {
		return nil, false
	}
	return o.PrivacyPolicyUrl, true
}

// HasPrivacyPolicyUrl returns a boolean if a field has been set.
func (o *BetaAppLocalizationUpdateRequestDataAttributes) HasPrivacyPolicyUrl() bool {
	if o != nil && !IsNil(o.PrivacyPolicyUrl) {
		return true
	}

	return false
}

// SetPrivacyPolicyUrl gets a reference to the given string and assigns it to the PrivacyPolicyUrl field.
func (o *BetaAppLocalizationUpdateRequestDataAttributes) SetPrivacyPolicyUrl(v string) {
	o.PrivacyPolicyUrl = &v
}

// GetTvOsPrivacyPolicy returns the TvOsPrivacyPolicy field value if set, zero value otherwise.
func (o *BetaAppLocalizationUpdateRequestDataAttributes) GetTvOsPrivacyPolicy() string {
	if o == nil || IsNil(o.TvOsPrivacyPolicy) {
		var ret string
		return ret
	}
	return *o.TvOsPrivacyPolicy
}

// GetTvOsPrivacyPolicyOk returns a tuple with the TvOsPrivacyPolicy field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *BetaAppLocalizationUpdateRequestDataAttributes) GetTvOsPrivacyPolicyOk() (*string, bool) {
	if o == nil || IsNil(o.TvOsPrivacyPolicy) {
		return nil, false
	}
	return o.TvOsPrivacyPolicy, true
}

// HasTvOsPrivacyPolicy returns a boolean if a field has been set.
func (o *BetaAppLocalizationUpdateRequestDataAttributes) HasTvOsPrivacyPolicy() bool {
	if o != nil && !IsNil(o.TvOsPrivacyPolicy) {
		return true
	}

	return false
}

// SetTvOsPrivacyPolicy gets a reference to the given string and assigns it to the TvOsPrivacyPolicy field.
func (o *BetaAppLocalizationUpdateRequestDataAttributes) SetTvOsPrivacyPolicy(v string) {
	o.TvOsPrivacyPolicy = &v
}

// GetDescription returns the Description field value if set, zero value otherwise.
func (o *BetaAppLocalizationUpdateRequestDataAttributes) GetDescription() string {
	if o == nil || IsNil(o.Description) {
		var ret string
		return ret
	}
	return *o.Description
}

// GetDescriptionOk returns a tuple with the Description field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *BetaAppLocalizationUpdateRequestDataAttributes) GetDescriptionOk() (*string, bool) {
	if o == nil || IsNil(o.Description) {
		return nil, false
	}
	return o.Description, true
}

// HasDescription returns a boolean if a field has been set.
func (o *BetaAppLocalizationUpdateRequestDataAttributes) HasDescription() bool {
	if o != nil && !IsNil(o.Description) {
		return true
	}

	return false
}

// SetDescription gets a reference to the given string and assigns it to the Description field.
func (o *BetaAppLocalizationUpdateRequestDataAttributes) SetDescription(v string) {
	o.Description = &v
}

func (o BetaAppLocalizationUpdateRequestDataAttributes) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o BetaAppLocalizationUpdateRequestDataAttributes) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.FeedbackEmail) {
		toSerialize["feedbackEmail"] = o.FeedbackEmail
	}
	if !IsNil(o.MarketingUrl) {
		toSerialize["marketingUrl"] = o.MarketingUrl
	}
	if !IsNil(o.PrivacyPolicyUrl) {
		toSerialize["privacyPolicyUrl"] = o.PrivacyPolicyUrl
	}
	if !IsNil(o.TvOsPrivacyPolicy) {
		toSerialize["tvOsPrivacyPolicy"] = o.TvOsPrivacyPolicy
	}
	if !IsNil(o.Description) {
		toSerialize["description"] = o.Description
	}
	return toSerialize, nil
}

type NullableBetaAppLocalizationUpdateRequestDataAttributes struct {
	value *BetaAppLocalizationUpdateRequestDataAttributes
	isSet bool
}

func (v NullableBetaAppLocalizationUpdateRequestDataAttributes) Get() *BetaAppLocalizationUpdateRequestDataAttributes {
	return v.value
}

func (v *NullableBetaAppLocalizationUpdateRequestDataAttributes) Set(val *BetaAppLocalizationUpdateRequestDataAttributes) {
	v.value = val
	v.isSet = true
}

func (v NullableBetaAppLocalizationUpdateRequestDataAttributes) IsSet() bool {
	return v.isSet
}

func (v *NullableBetaAppLocalizationUpdateRequestDataAttributes) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableBetaAppLocalizationUpdateRequestDataAttributes(val *BetaAppLocalizationUpdateRequestDataAttributes) *NullableBetaAppLocalizationUpdateRequestDataAttributes {
	return &NullableBetaAppLocalizationUpdateRequestDataAttributes{value: val, isSet: true}
}

func (v NullableBetaAppLocalizationUpdateRequestDataAttributes) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableBetaAppLocalizationUpdateRequestDataAttributes) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
