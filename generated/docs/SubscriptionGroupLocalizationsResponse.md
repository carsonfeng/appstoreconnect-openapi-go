# SubscriptionGroupLocalizationsResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**[]SubscriptionGroupLocalization**](SubscriptionGroupLocalization.md) |  | 
**Included** | Pointer to [**[]SubscriptionGroup**](SubscriptionGroup.md) |  | [optional] 
**Links** | [**PagedDocumentLinks**](PagedDocumentLinks.md) |  | 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 

## Methods

### NewSubscriptionGroupLocalizationsResponse

`func NewSubscriptionGroupLocalizationsResponse(data []SubscriptionGroupLocalization, links PagedDocumentLinks, ) *SubscriptionGroupLocalizationsResponse`

NewSubscriptionGroupLocalizationsResponse instantiates a new SubscriptionGroupLocalizationsResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionGroupLocalizationsResponseWithDefaults

`func NewSubscriptionGroupLocalizationsResponseWithDefaults() *SubscriptionGroupLocalizationsResponse`

NewSubscriptionGroupLocalizationsResponseWithDefaults instantiates a new SubscriptionGroupLocalizationsResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *SubscriptionGroupLocalizationsResponse) GetData() []SubscriptionGroupLocalization`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *SubscriptionGroupLocalizationsResponse) GetDataOk() (*[]SubscriptionGroupLocalization, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *SubscriptionGroupLocalizationsResponse) SetData(v []SubscriptionGroupLocalization)`

SetData sets Data field to given value.


### GetIncluded

`func (o *SubscriptionGroupLocalizationsResponse) GetIncluded() []SubscriptionGroup`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *SubscriptionGroupLocalizationsResponse) GetIncludedOk() (*[]SubscriptionGroup, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *SubscriptionGroupLocalizationsResponse) SetIncluded(v []SubscriptionGroup)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *SubscriptionGroupLocalizationsResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *SubscriptionGroupLocalizationsResponse) GetLinks() PagedDocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *SubscriptionGroupLocalizationsResponse) GetLinksOk() (*PagedDocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *SubscriptionGroupLocalizationsResponse) SetLinks(v PagedDocumentLinks)`

SetLinks sets Links field to given value.


### GetMeta

`func (o *SubscriptionGroupLocalizationsResponse) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *SubscriptionGroupLocalizationsResponse) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *SubscriptionGroupLocalizationsResponse) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *SubscriptionGroupLocalizationsResponse) HasMeta() bool`

HasMeta returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


