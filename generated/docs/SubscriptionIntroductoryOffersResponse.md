# SubscriptionIntroductoryOffersResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**[]SubscriptionIntroductoryOffer**](SubscriptionIntroductoryOffer.md) |  | 
**Included** | Pointer to [**[]SubscriptionIntroductoryOffersResponseIncludedInner**](SubscriptionIntroductoryOffersResponseIncludedInner.md) |  | [optional] 
**Links** | [**PagedDocumentLinks**](PagedDocumentLinks.md) |  | 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 

## Methods

### NewSubscriptionIntroductoryOffersResponse

`func NewSubscriptionIntroductoryOffersResponse(data []SubscriptionIntroductoryOffer, links PagedDocumentLinks, ) *SubscriptionIntroductoryOffersResponse`

NewSubscriptionIntroductoryOffersResponse instantiates a new SubscriptionIntroductoryOffersResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionIntroductoryOffersResponseWithDefaults

`func NewSubscriptionIntroductoryOffersResponseWithDefaults() *SubscriptionIntroductoryOffersResponse`

NewSubscriptionIntroductoryOffersResponseWithDefaults instantiates a new SubscriptionIntroductoryOffersResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *SubscriptionIntroductoryOffersResponse) GetData() []SubscriptionIntroductoryOffer`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *SubscriptionIntroductoryOffersResponse) GetDataOk() (*[]SubscriptionIntroductoryOffer, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *SubscriptionIntroductoryOffersResponse) SetData(v []SubscriptionIntroductoryOffer)`

SetData sets Data field to given value.


### GetIncluded

`func (o *SubscriptionIntroductoryOffersResponse) GetIncluded() []SubscriptionIntroductoryOffersResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *SubscriptionIntroductoryOffersResponse) GetIncludedOk() (*[]SubscriptionIntroductoryOffersResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *SubscriptionIntroductoryOffersResponse) SetIncluded(v []SubscriptionIntroductoryOffersResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *SubscriptionIntroductoryOffersResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *SubscriptionIntroductoryOffersResponse) GetLinks() PagedDocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *SubscriptionIntroductoryOffersResponse) GetLinksOk() (*PagedDocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *SubscriptionIntroductoryOffersResponse) SetLinks(v PagedDocumentLinks)`

SetLinks sets Links field to given value.


### GetMeta

`func (o *SubscriptionIntroductoryOffersResponse) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *SubscriptionIntroductoryOffersResponse) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *SubscriptionIntroductoryOffersResponse) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *SubscriptionIntroductoryOffersResponse) HasMeta() bool`

HasMeta returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


