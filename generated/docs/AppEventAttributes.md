# AppEventAttributes

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**ReferenceName** | Pointer to **string** |  | [optional] 
**Badge** | Pointer to **string** |  | [optional] 
**EventState** | Pointer to **string** |  | [optional] 
**DeepLink** | Pointer to **string** |  | [optional] 
**PurchaseRequirement** | Pointer to **string** |  | [optional] 
**PrimaryLocale** | Pointer to **string** |  | [optional] 
**Priority** | Pointer to **string** |  | [optional] 
**Purpose** | Pointer to **string** |  | [optional] 
**TerritorySchedules** | Pointer to [**[]AppEventAttributesTerritorySchedulesInner**](AppEventAttributesTerritorySchedulesInner.md) |  | [optional] 
**ArchivedTerritorySchedules** | Pointer to [**[]AppEventAttributesTerritorySchedulesInner**](AppEventAttributesTerritorySchedulesInner.md) |  | [optional] 

## Methods

### NewAppEventAttributes

`func NewAppEventAttributes() *AppEventAttributes`

NewAppEventAttributes instantiates a new AppEventAttributes object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppEventAttributesWithDefaults

`func NewAppEventAttributesWithDefaults() *AppEventAttributes`

NewAppEventAttributesWithDefaults instantiates a new AppEventAttributes object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetReferenceName

`func (o *AppEventAttributes) GetReferenceName() string`

GetReferenceName returns the ReferenceName field if non-nil, zero value otherwise.

### GetReferenceNameOk

`func (o *AppEventAttributes) GetReferenceNameOk() (*string, bool)`

GetReferenceNameOk returns a tuple with the ReferenceName field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetReferenceName

`func (o *AppEventAttributes) SetReferenceName(v string)`

SetReferenceName sets ReferenceName field to given value.

### HasReferenceName

`func (o *AppEventAttributes) HasReferenceName() bool`

HasReferenceName returns a boolean if a field has been set.

### GetBadge

`func (o *AppEventAttributes) GetBadge() string`

GetBadge returns the Badge field if non-nil, zero value otherwise.

### GetBadgeOk

`func (o *AppEventAttributes) GetBadgeOk() (*string, bool)`

GetBadgeOk returns a tuple with the Badge field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetBadge

`func (o *AppEventAttributes) SetBadge(v string)`

SetBadge sets Badge field to given value.

### HasBadge

`func (o *AppEventAttributes) HasBadge() bool`

HasBadge returns a boolean if a field has been set.

### GetEventState

`func (o *AppEventAttributes) GetEventState() string`

GetEventState returns the EventState field if non-nil, zero value otherwise.

### GetEventStateOk

`func (o *AppEventAttributes) GetEventStateOk() (*string, bool)`

GetEventStateOk returns a tuple with the EventState field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetEventState

`func (o *AppEventAttributes) SetEventState(v string)`

SetEventState sets EventState field to given value.

### HasEventState

`func (o *AppEventAttributes) HasEventState() bool`

HasEventState returns a boolean if a field has been set.

### GetDeepLink

`func (o *AppEventAttributes) GetDeepLink() string`

GetDeepLink returns the DeepLink field if non-nil, zero value otherwise.

### GetDeepLinkOk

`func (o *AppEventAttributes) GetDeepLinkOk() (*string, bool)`

GetDeepLinkOk returns a tuple with the DeepLink field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDeepLink

`func (o *AppEventAttributes) SetDeepLink(v string)`

SetDeepLink sets DeepLink field to given value.

### HasDeepLink

`func (o *AppEventAttributes) HasDeepLink() bool`

HasDeepLink returns a boolean if a field has been set.

### GetPurchaseRequirement

`func (o *AppEventAttributes) GetPurchaseRequirement() string`

GetPurchaseRequirement returns the PurchaseRequirement field if non-nil, zero value otherwise.

### GetPurchaseRequirementOk

`func (o *AppEventAttributes) GetPurchaseRequirementOk() (*string, bool)`

GetPurchaseRequirementOk returns a tuple with the PurchaseRequirement field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPurchaseRequirement

`func (o *AppEventAttributes) SetPurchaseRequirement(v string)`

SetPurchaseRequirement sets PurchaseRequirement field to given value.

### HasPurchaseRequirement

`func (o *AppEventAttributes) HasPurchaseRequirement() bool`

HasPurchaseRequirement returns a boolean if a field has been set.

### GetPrimaryLocale

`func (o *AppEventAttributes) GetPrimaryLocale() string`

GetPrimaryLocale returns the PrimaryLocale field if non-nil, zero value otherwise.

### GetPrimaryLocaleOk

`func (o *AppEventAttributes) GetPrimaryLocaleOk() (*string, bool)`

GetPrimaryLocaleOk returns a tuple with the PrimaryLocale field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPrimaryLocale

`func (o *AppEventAttributes) SetPrimaryLocale(v string)`

SetPrimaryLocale sets PrimaryLocale field to given value.

### HasPrimaryLocale

`func (o *AppEventAttributes) HasPrimaryLocale() bool`

HasPrimaryLocale returns a boolean if a field has been set.

### GetPriority

`func (o *AppEventAttributes) GetPriority() string`

GetPriority returns the Priority field if non-nil, zero value otherwise.

### GetPriorityOk

`func (o *AppEventAttributes) GetPriorityOk() (*string, bool)`

GetPriorityOk returns a tuple with the Priority field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPriority

`func (o *AppEventAttributes) SetPriority(v string)`

SetPriority sets Priority field to given value.

### HasPriority

`func (o *AppEventAttributes) HasPriority() bool`

HasPriority returns a boolean if a field has been set.

### GetPurpose

`func (o *AppEventAttributes) GetPurpose() string`

GetPurpose returns the Purpose field if non-nil, zero value otherwise.

### GetPurposeOk

`func (o *AppEventAttributes) GetPurposeOk() (*string, bool)`

GetPurposeOk returns a tuple with the Purpose field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPurpose

`func (o *AppEventAttributes) SetPurpose(v string)`

SetPurpose sets Purpose field to given value.

### HasPurpose

`func (o *AppEventAttributes) HasPurpose() bool`

HasPurpose returns a boolean if a field has been set.

### GetTerritorySchedules

`func (o *AppEventAttributes) GetTerritorySchedules() []AppEventAttributesTerritorySchedulesInner`

GetTerritorySchedules returns the TerritorySchedules field if non-nil, zero value otherwise.

### GetTerritorySchedulesOk

`func (o *AppEventAttributes) GetTerritorySchedulesOk() (*[]AppEventAttributesTerritorySchedulesInner, bool)`

GetTerritorySchedulesOk returns a tuple with the TerritorySchedules field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTerritorySchedules

`func (o *AppEventAttributes) SetTerritorySchedules(v []AppEventAttributesTerritorySchedulesInner)`

SetTerritorySchedules sets TerritorySchedules field to given value.

### HasTerritorySchedules

`func (o *AppEventAttributes) HasTerritorySchedules() bool`

HasTerritorySchedules returns a boolean if a field has been set.

### GetArchivedTerritorySchedules

`func (o *AppEventAttributes) GetArchivedTerritorySchedules() []AppEventAttributesTerritorySchedulesInner`

GetArchivedTerritorySchedules returns the ArchivedTerritorySchedules field if non-nil, zero value otherwise.

### GetArchivedTerritorySchedulesOk

`func (o *AppEventAttributes) GetArchivedTerritorySchedulesOk() (*[]AppEventAttributesTerritorySchedulesInner, bool)`

GetArchivedTerritorySchedulesOk returns a tuple with the ArchivedTerritorySchedules field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetArchivedTerritorySchedules

`func (o *AppEventAttributes) SetArchivedTerritorySchedules(v []AppEventAttributesTerritorySchedulesInner)`

SetArchivedTerritorySchedules sets ArchivedTerritorySchedules field to given value.

### HasArchivedTerritorySchedules

`func (o *AppEventAttributes) HasArchivedTerritorySchedules() bool`

HasArchivedTerritorySchedules returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


