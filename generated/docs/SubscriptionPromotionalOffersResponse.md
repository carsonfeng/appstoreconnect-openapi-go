# SubscriptionPromotionalOffersResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**[]SubscriptionPromotionalOffer**](SubscriptionPromotionalOffer.md) |  | 
**Included** | Pointer to [**[]SubscriptionPromotionalOffersResponseIncludedInner**](SubscriptionPromotionalOffersResponseIncludedInner.md) |  | [optional] 
**Links** | [**PagedDocumentLinks**](PagedDocumentLinks.md) |  | 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 

## Methods

### NewSubscriptionPromotionalOffersResponse

`func NewSubscriptionPromotionalOffersResponse(data []SubscriptionPromotionalOffer, links PagedDocumentLinks, ) *SubscriptionPromotionalOffersResponse`

NewSubscriptionPromotionalOffersResponse instantiates a new SubscriptionPromotionalOffersResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionPromotionalOffersResponseWithDefaults

`func NewSubscriptionPromotionalOffersResponseWithDefaults() *SubscriptionPromotionalOffersResponse`

NewSubscriptionPromotionalOffersResponseWithDefaults instantiates a new SubscriptionPromotionalOffersResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *SubscriptionPromotionalOffersResponse) GetData() []SubscriptionPromotionalOffer`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *SubscriptionPromotionalOffersResponse) GetDataOk() (*[]SubscriptionPromotionalOffer, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *SubscriptionPromotionalOffersResponse) SetData(v []SubscriptionPromotionalOffer)`

SetData sets Data field to given value.


### GetIncluded

`func (o *SubscriptionPromotionalOffersResponse) GetIncluded() []SubscriptionPromotionalOffersResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *SubscriptionPromotionalOffersResponse) GetIncludedOk() (*[]SubscriptionPromotionalOffersResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *SubscriptionPromotionalOffersResponse) SetIncluded(v []SubscriptionPromotionalOffersResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *SubscriptionPromotionalOffersResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *SubscriptionPromotionalOffersResponse) GetLinks() PagedDocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *SubscriptionPromotionalOffersResponse) GetLinksOk() (*PagedDocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *SubscriptionPromotionalOffersResponse) SetLinks(v PagedDocumentLinks)`

SetLinks sets Links field to given value.


### GetMeta

`func (o *SubscriptionPromotionalOffersResponse) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *SubscriptionPromotionalOffersResponse) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *SubscriptionPromotionalOffersResponse) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *SubscriptionPromotionalOffersResponse) HasMeta() bool`

HasMeta returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


