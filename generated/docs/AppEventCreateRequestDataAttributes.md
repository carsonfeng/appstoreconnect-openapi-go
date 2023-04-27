# AppEventCreateRequestDataAttributes

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**ReferenceName** | **string** |  | 
**Badge** | Pointer to **string** |  | [optional] 
**DeepLink** | Pointer to **string** |  | [optional] 
**PurchaseRequirement** | Pointer to **string** |  | [optional] 
**PrimaryLocale** | Pointer to **string** |  | [optional] 
**Priority** | Pointer to **string** |  | [optional] 
**Purpose** | Pointer to **string** |  | [optional] 
**TerritorySchedules** | Pointer to [**[]AppEventAttributesTerritorySchedulesInner**](AppEventAttributesTerritorySchedulesInner.md) |  | [optional] 

## Methods

### NewAppEventCreateRequestDataAttributes

`func NewAppEventCreateRequestDataAttributes(referenceName string, ) *AppEventCreateRequestDataAttributes`

NewAppEventCreateRequestDataAttributes instantiates a new AppEventCreateRequestDataAttributes object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppEventCreateRequestDataAttributesWithDefaults

`func NewAppEventCreateRequestDataAttributesWithDefaults() *AppEventCreateRequestDataAttributes`

NewAppEventCreateRequestDataAttributesWithDefaults instantiates a new AppEventCreateRequestDataAttributes object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetReferenceName

`func (o *AppEventCreateRequestDataAttributes) GetReferenceName() string`

GetReferenceName returns the ReferenceName field if non-nil, zero value otherwise.

### GetReferenceNameOk

`func (o *AppEventCreateRequestDataAttributes) GetReferenceNameOk() (*string, bool)`

GetReferenceNameOk returns a tuple with the ReferenceName field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetReferenceName

`func (o *AppEventCreateRequestDataAttributes) SetReferenceName(v string)`

SetReferenceName sets ReferenceName field to given value.


### GetBadge

`func (o *AppEventCreateRequestDataAttributes) GetBadge() string`

GetBadge returns the Badge field if non-nil, zero value otherwise.

### GetBadgeOk

`func (o *AppEventCreateRequestDataAttributes) GetBadgeOk() (*string, bool)`

GetBadgeOk returns a tuple with the Badge field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetBadge

`func (o *AppEventCreateRequestDataAttributes) SetBadge(v string)`

SetBadge sets Badge field to given value.

### HasBadge

`func (o *AppEventCreateRequestDataAttributes) HasBadge() bool`

HasBadge returns a boolean if a field has been set.

### GetDeepLink

`func (o *AppEventCreateRequestDataAttributes) GetDeepLink() string`

GetDeepLink returns the DeepLink field if non-nil, zero value otherwise.

### GetDeepLinkOk

`func (o *AppEventCreateRequestDataAttributes) GetDeepLinkOk() (*string, bool)`

GetDeepLinkOk returns a tuple with the DeepLink field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDeepLink

`func (o *AppEventCreateRequestDataAttributes) SetDeepLink(v string)`

SetDeepLink sets DeepLink field to given value.

### HasDeepLink

`func (o *AppEventCreateRequestDataAttributes) HasDeepLink() bool`

HasDeepLink returns a boolean if a field has been set.

### GetPurchaseRequirement

`func (o *AppEventCreateRequestDataAttributes) GetPurchaseRequirement() string`

GetPurchaseRequirement returns the PurchaseRequirement field if non-nil, zero value otherwise.

### GetPurchaseRequirementOk

`func (o *AppEventCreateRequestDataAttributes) GetPurchaseRequirementOk() (*string, bool)`

GetPurchaseRequirementOk returns a tuple with the PurchaseRequirement field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPurchaseRequirement

`func (o *AppEventCreateRequestDataAttributes) SetPurchaseRequirement(v string)`

SetPurchaseRequirement sets PurchaseRequirement field to given value.

### HasPurchaseRequirement

`func (o *AppEventCreateRequestDataAttributes) HasPurchaseRequirement() bool`

HasPurchaseRequirement returns a boolean if a field has been set.

### GetPrimaryLocale

`func (o *AppEventCreateRequestDataAttributes) GetPrimaryLocale() string`

GetPrimaryLocale returns the PrimaryLocale field if non-nil, zero value otherwise.

### GetPrimaryLocaleOk

`func (o *AppEventCreateRequestDataAttributes) GetPrimaryLocaleOk() (*string, bool)`

GetPrimaryLocaleOk returns a tuple with the PrimaryLocale field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPrimaryLocale

`func (o *AppEventCreateRequestDataAttributes) SetPrimaryLocale(v string)`

SetPrimaryLocale sets PrimaryLocale field to given value.

### HasPrimaryLocale

`func (o *AppEventCreateRequestDataAttributes) HasPrimaryLocale() bool`

HasPrimaryLocale returns a boolean if a field has been set.

### GetPriority

`func (o *AppEventCreateRequestDataAttributes) GetPriority() string`

GetPriority returns the Priority field if non-nil, zero value otherwise.

### GetPriorityOk

`func (o *AppEventCreateRequestDataAttributes) GetPriorityOk() (*string, bool)`

GetPriorityOk returns a tuple with the Priority field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPriority

`func (o *AppEventCreateRequestDataAttributes) SetPriority(v string)`

SetPriority sets Priority field to given value.

### HasPriority

`func (o *AppEventCreateRequestDataAttributes) HasPriority() bool`

HasPriority returns a boolean if a field has been set.

### GetPurpose

`func (o *AppEventCreateRequestDataAttributes) GetPurpose() string`

GetPurpose returns the Purpose field if non-nil, zero value otherwise.

### GetPurposeOk

`func (o *AppEventCreateRequestDataAttributes) GetPurposeOk() (*string, bool)`

GetPurposeOk returns a tuple with the Purpose field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPurpose

`func (o *AppEventCreateRequestDataAttributes) SetPurpose(v string)`

SetPurpose sets Purpose field to given value.

### HasPurpose

`func (o *AppEventCreateRequestDataAttributes) HasPurpose() bool`

HasPurpose returns a boolean if a field has been set.

### GetTerritorySchedules

`func (o *AppEventCreateRequestDataAttributes) GetTerritorySchedules() []AppEventAttributesTerritorySchedulesInner`

GetTerritorySchedules returns the TerritorySchedules field if non-nil, zero value otherwise.

### GetTerritorySchedulesOk

`func (o *AppEventCreateRequestDataAttributes) GetTerritorySchedulesOk() (*[]AppEventAttributesTerritorySchedulesInner, bool)`

GetTerritorySchedulesOk returns a tuple with the TerritorySchedules field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTerritorySchedules

`func (o *AppEventCreateRequestDataAttributes) SetTerritorySchedules(v []AppEventAttributesTerritorySchedulesInner)`

SetTerritorySchedules sets TerritorySchedules field to given value.

### HasTerritorySchedules

`func (o *AppEventCreateRequestDataAttributes) HasTerritorySchedules() bool`

HasTerritorySchedules returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


