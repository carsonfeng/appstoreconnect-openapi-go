# SubscriptionLocalizationsResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**[]SubscriptionLocalization**](SubscriptionLocalization.md) |  | 
**Included** | Pointer to [**[]Subscription**](Subscription.md) |  | [optional] 
**Links** | [**PagedDocumentLinks**](PagedDocumentLinks.md) |  | 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 

## Methods

### NewSubscriptionLocalizationsResponse

`func NewSubscriptionLocalizationsResponse(data []SubscriptionLocalization, links PagedDocumentLinks, ) *SubscriptionLocalizationsResponse`

NewSubscriptionLocalizationsResponse instantiates a new SubscriptionLocalizationsResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionLocalizationsResponseWithDefaults

`func NewSubscriptionLocalizationsResponseWithDefaults() *SubscriptionLocalizationsResponse`

NewSubscriptionLocalizationsResponseWithDefaults instantiates a new SubscriptionLocalizationsResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *SubscriptionLocalizationsResponse) GetData() []SubscriptionLocalization`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *SubscriptionLocalizationsResponse) GetDataOk() (*[]SubscriptionLocalization, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *SubscriptionLocalizationsResponse) SetData(v []SubscriptionLocalization)`

SetData sets Data field to given value.


### GetIncluded

`func (o *SubscriptionLocalizationsResponse) GetIncluded() []Subscription`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *SubscriptionLocalizationsResponse) GetIncludedOk() (*[]Subscription, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *SubscriptionLocalizationsResponse) SetIncluded(v []Subscription)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *SubscriptionLocalizationsResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *SubscriptionLocalizationsResponse) GetLinks() PagedDocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *SubscriptionLocalizationsResponse) GetLinksOk() (*PagedDocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *SubscriptionLocalizationsResponse) SetLinks(v PagedDocumentLinks)`

SetLinks sets Links field to given value.


### GetMeta

`func (o *SubscriptionLocalizationsResponse) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *SubscriptionLocalizationsResponse) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *SubscriptionLocalizationsResponse) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *SubscriptionLocalizationsResponse) HasMeta() bool`

HasMeta returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


