# AppEventUpdateRequestDataAttributes

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**ReferenceName** | Pointer to **string** |  | [optional] 
**Badge** | Pointer to **string** |  | [optional] 
**DeepLink** | Pointer to **string** |  | [optional] 
**PurchaseRequirement** | Pointer to **string** |  | [optional] 
**PrimaryLocale** | Pointer to **string** |  | [optional] 
**Priority** | Pointer to **string** |  | [optional] 
**Purpose** | Pointer to **string** |  | [optional] 
**TerritorySchedules** | Pointer to [**[]AppEventAttributesTerritorySchedulesInner**](AppEventAttributesTerritorySchedulesInner.md) |  | [optional] 

## Methods

### NewAppEventUpdateRequestDataAttributes

`func NewAppEventUpdateRequestDataAttributes() *AppEventUpdateRequestDataAttributes`

NewAppEventUpdateRequestDataAttributes instantiates a new AppEventUpdateRequestDataAttributes object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppEventUpdateRequestDataAttributesWithDefaults

`func NewAppEventUpdateRequestDataAttributesWithDefaults() *AppEventUpdateRequestDataAttributes`

NewAppEventUpdateRequestDataAttributesWithDefaults instantiates a new AppEventUpdateRequestDataAttributes object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetReferenceName

`func (o *AppEventUpdateRequestDataAttributes) GetReferenceName() string`

GetReferenceName returns the ReferenceName field if non-nil, zero value otherwise.

### GetReferenceNameOk

`func (o *AppEventUpdateRequestDataAttributes) GetReferenceNameOk() (*string, bool)`

GetReferenceNameOk returns a tuple with the ReferenceName field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetReferenceName

`func (o *AppEventUpdateRequestDataAttributes) SetReferenceName(v string)`

SetReferenceName sets ReferenceName field to given value.

### HasReferenceName

`func (o *AppEventUpdateRequestDataAttributes) HasReferenceName() bool`

HasReferenceName returns a boolean if a field has been set.

### GetBadge

`func (o *AppEventUpdateRequestDataAttributes) GetBadge() string`

GetBadge returns the Badge field if non-nil, zero value otherwise.

### GetBadgeOk

`func (o *AppEventUpdateRequestDataAttributes) GetBadgeOk() (*string, bool)`

GetBadgeOk returns a tuple with the Badge field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetBadge

`func (o *AppEventUpdateRequestDataAttributes) SetBadge(v string)`

SetBadge sets Badge field to given value.

### HasBadge

`func (o *AppEventUpdateRequestDataAttributes) HasBadge() bool`

HasBadge returns a boolean if a field has been set.

### GetDeepLink

`func (o *AppEventUpdateRequestDataAttributes) GetDeepLink() string`

GetDeepLink returns the DeepLink field if non-nil, zero value otherwise.

### GetDeepLinkOk

`func (o *AppEventUpdateRequestDataAttributes) GetDeepLinkOk() (*string, bool)`

GetDeepLinkOk returns a tuple with the DeepLink field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDeepLink

`func (o *AppEventUpdateRequestDataAttributes) SetDeepLink(v string)`

SetDeepLink sets DeepLink field to given value.

### HasDeepLink

`func (o *AppEventUpdateRequestDataAttributes) HasDeepLink() bool`

HasDeepLink returns a boolean if a field has been set.

### GetPurchaseRequirement

`func (o *AppEventUpdateRequestDataAttributes) GetPurchaseRequirement() string`

GetPurchaseRequirement returns the PurchaseRequirement field if non-nil, zero value otherwise.

### GetPurchaseRequirementOk

`func (o *AppEventUpdateRequestDataAttributes) GetPurchaseRequirementOk() (*string, bool)`

GetPurchaseRequirementOk returns a tuple with the PurchaseRequirement field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPurchaseRequirement

`func (o *AppEventUpdateRequestDataAttributes) SetPurchaseRequirement(v string)`

SetPurchaseRequirement sets PurchaseRequirement field to given value.

### HasPurchaseRequirement

`func (o *AppEventUpdateRequestDataAttributes) HasPurchaseRequirement() bool`

HasPurchaseRequirement returns a boolean if a field has been set.

### GetPrimaryLocale

`func (o *AppEventUpdateRequestDataAttributes) GetPrimaryLocale() string`

GetPrimaryLocale returns the PrimaryLocale field if non-nil, zero value otherwise.

### GetPrimaryLocaleOk

`func (o *AppEventUpdateRequestDataAttributes) GetPrimaryLocaleOk() (*string, bool)`

GetPrimaryLocaleOk returns a tuple with the PrimaryLocale field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPrimaryLocale

`func (o *AppEventUpdateRequestDataAttributes) SetPrimaryLocale(v string)`

SetPrimaryLocale sets PrimaryLocale field to given value.

### HasPrimaryLocale

`func (o *AppEventUpdateRequestDataAttributes) HasPrimaryLocale() bool`

HasPrimaryLocale returns a boolean if a field has been set.

### GetPriority

`func (o *AppEventUpdateRequestDataAttributes) GetPriority() string`

GetPriority returns the Priority field if non-nil, zero value otherwise.

### GetPriorityOk

`func (o *AppEventUpdateRequestDataAttributes) GetPriorityOk() (*string, bool)`

GetPriorityOk returns a tuple with the Priority field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPriority

`func (o *AppEventUpdateRequestDataAttributes) SetPriority(v string)`

SetPriority sets Priority field to given value.

### HasPriority

`func (o *AppEventUpdateRequestDataAttributes) HasPriority() bool`

HasPriority returns a boolean if a field has been set.

### GetPurpose

`func (o *AppEventUpdateRequestDataAttributes) GetPurpose() string`

GetPurpose returns the Purpose field if non-nil, zero value otherwise.

### GetPurposeOk

`func (o *AppEventUpdateRequestDataAttributes) GetPurposeOk() (*string, bool)`

GetPurposeOk returns a tuple with the Purpose field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPurpose

`func (o *AppEventUpdateRequestDataAttributes) SetPurpose(v string)`

SetPurpose sets Purpose field to given value.

### HasPurpose

`func (o *AppEventUpdateRequestDataAttributes) HasPurpose() bool`

HasPurpose returns a boolean if a field has been set.

### GetTerritorySchedules

`func (o *AppEventUpdateRequestDataAttributes) GetTerritorySchedules() []AppEventAttributesTerritorySchedulesInner`

GetTerritorySchedules returns the TerritorySchedules field if non-nil, zero value otherwise.

### GetTerritorySchedulesOk

`func (o *AppEventUpdateRequestDataAttributes) GetTerritorySchedulesOk() (*[]AppEventAttributesTerritorySchedulesInner, bool)`

GetTerritorySchedulesOk returns a tuple with the TerritorySchedules field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTerritorySchedules

`func (o *AppEventUpdateRequestDataAttributes) SetTerritorySchedules(v []AppEventAttributesTerritorySchedulesInner)`

SetTerritorySchedules sets TerritorySchedules field to given value.

### HasTerritorySchedules

`func (o *AppEventUpdateRequestDataAttributes) HasTerritorySchedules() bool`

HasTerritorySchedules returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


