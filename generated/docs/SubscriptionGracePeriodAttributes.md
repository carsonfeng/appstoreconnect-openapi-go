# SubscriptionGracePeriodAttributes

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**OptIn** | Pointer to **bool** |  | [optional] 
**SandboxOptIn** | Pointer to **bool** |  | [optional] 
**Duration** | Pointer to [**SubscriptionGracePeriodDuration**](SubscriptionGracePeriodDuration.md) |  | [optional] 
**RenewalType** | Pointer to **string** |  | [optional] 

## Methods

### NewSubscriptionGracePeriodAttributes

`func NewSubscriptionGracePeriodAttributes() *SubscriptionGracePeriodAttributes`

NewSubscriptionGracePeriodAttributes instantiates a new SubscriptionGracePeriodAttributes object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionGracePeriodAttributesWithDefaults

`func NewSubscriptionGracePeriodAttributesWithDefaults() *SubscriptionGracePeriodAttributes`

NewSubscriptionGracePeriodAttributesWithDefaults instantiates a new SubscriptionGracePeriodAttributes object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetOptIn

`func (o *SubscriptionGracePeriodAttributes) GetOptIn() bool`

GetOptIn returns the OptIn field if non-nil, zero value otherwise.

### GetOptInOk

`func (o *SubscriptionGracePeriodAttributes) GetOptInOk() (*bool, bool)`

GetOptInOk returns a tuple with the OptIn field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetOptIn

`func (o *SubscriptionGracePeriodAttributes) SetOptIn(v bool)`

SetOptIn sets OptIn field to given value.

### HasOptIn

`func (o *SubscriptionGracePeriodAttributes) HasOptIn() bool`

HasOptIn returns a boolean if a field has been set.

### GetSandboxOptIn

`func (o *SubscriptionGracePeriodAttributes) GetSandboxOptIn() bool`

GetSandboxOptIn returns the SandboxOptIn field if non-nil, zero value otherwise.

### GetSandboxOptInOk

`func (o *SubscriptionGracePeriodAttributes) GetSandboxOptInOk() (*bool, bool)`

GetSandboxOptInOk returns a tuple with the SandboxOptIn field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSandboxOptIn

`func (o *SubscriptionGracePeriodAttributes) SetSandboxOptIn(v bool)`

SetSandboxOptIn sets SandboxOptIn field to given value.

### HasSandboxOptIn

`func (o *SubscriptionGracePeriodAttributes) HasSandboxOptIn() bool`

HasSandboxOptIn returns a boolean if a field has been set.

### GetDuration

`func (o *SubscriptionGracePeriodAttributes) GetDuration() SubscriptionGracePeriodDuration`

GetDuration returns the Duration field if non-nil, zero value otherwise.

### GetDurationOk

`func (o *SubscriptionGracePeriodAttributes) GetDurationOk() (*SubscriptionGracePeriodDuration, bool)`

GetDurationOk returns a tuple with the Duration field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDuration

`func (o *SubscriptionGracePeriodAttributes) SetDuration(v SubscriptionGracePeriodDuration)`

SetDuration sets Duration field to given value.

### HasDuration

`func (o *SubscriptionGracePeriodAttributes) HasDuration() bool`

HasDuration returns a boolean if a field has been set.

### GetRenewalType

`func (o *SubscriptionGracePeriodAttributes) GetRenewalType() string`

GetRenewalType returns the RenewalType field if non-nil, zero value otherwise.

### GetRenewalTypeOk

`func (o *SubscriptionGracePeriodAttributes) GetRenewalTypeOk() (*string, bool)`

GetRenewalTypeOk returns a tuple with the RenewalType field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRenewalType

`func (o *SubscriptionGracePeriodAttributes) SetRenewalType(v string)`

SetRenewalType sets RenewalType field to given value.

### HasRenewalType

`func (o *SubscriptionGracePeriodAttributes) HasRenewalType() bool`

HasRenewalType returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


