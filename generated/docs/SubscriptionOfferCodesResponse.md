# SubscriptionOfferCodesResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**[]SubscriptionOfferCode**](SubscriptionOfferCode.md) |  | 
**Included** | Pointer to [**[]SubscriptionOfferCodesResponseIncludedInner**](SubscriptionOfferCodesResponseIncludedInner.md) |  | [optional] 
**Links** | [**PagedDocumentLinks**](PagedDocumentLinks.md) |  | 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 

## Methods

### NewSubscriptionOfferCodesResponse

`func NewSubscriptionOfferCodesResponse(data []SubscriptionOfferCode, links PagedDocumentLinks, ) *SubscriptionOfferCodesResponse`

NewSubscriptionOfferCodesResponse instantiates a new SubscriptionOfferCodesResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionOfferCodesResponseWithDefaults

`func NewSubscriptionOfferCodesResponseWithDefaults() *SubscriptionOfferCodesResponse`

NewSubscriptionOfferCodesResponseWithDefaults instantiates a new SubscriptionOfferCodesResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *SubscriptionOfferCodesResponse) GetData() []SubscriptionOfferCode`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *SubscriptionOfferCodesResponse) GetDataOk() (*[]SubscriptionOfferCode, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *SubscriptionOfferCodesResponse) SetData(v []SubscriptionOfferCode)`

SetData sets Data field to given value.


### GetIncluded

`func (o *SubscriptionOfferCodesResponse) GetIncluded() []SubscriptionOfferCodesResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *SubscriptionOfferCodesResponse) GetIncludedOk() (*[]SubscriptionOfferCodesResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *SubscriptionOfferCodesResponse) SetIncluded(v []SubscriptionOfferCodesResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *SubscriptionOfferCodesResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *SubscriptionOfferCodesResponse) GetLinks() PagedDocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *SubscriptionOfferCodesResponse) GetLinksOk() (*PagedDocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *SubscriptionOfferCodesResponse) SetLinks(v PagedDocumentLinks)`

SetLinks sets Links field to given value.


### GetMeta

`func (o *SubscriptionOfferCodesResponse) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *SubscriptionOfferCodesResponse) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *SubscriptionOfferCodesResponse) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *SubscriptionOfferCodesResponse) HasMeta() bool`

HasMeta returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


