# SubscriptionIntroductoryOffersLinkagesResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**[]SubscriptionRelationshipsIntroductoryOffersDataInner**](SubscriptionRelationshipsIntroductoryOffersDataInner.md) |  | 
**Links** | [**PagedDocumentLinks**](PagedDocumentLinks.md) |  | 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 

## Methods

### NewSubscriptionIntroductoryOffersLinkagesResponse

`func NewSubscriptionIntroductoryOffersLinkagesResponse(data []SubscriptionRelationshipsIntroductoryOffersDataInner, links PagedDocumentLinks, ) *SubscriptionIntroductoryOffersLinkagesResponse`

NewSubscriptionIntroductoryOffersLinkagesResponse instantiates a new SubscriptionIntroductoryOffersLinkagesResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionIntroductoryOffersLinkagesResponseWithDefaults

`func NewSubscriptionIntroductoryOffersLinkagesResponseWithDefaults() *SubscriptionIntroductoryOffersLinkagesResponse`

NewSubscriptionIntroductoryOffersLinkagesResponseWithDefaults instantiates a new SubscriptionIntroductoryOffersLinkagesResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *SubscriptionIntroductoryOffersLinkagesResponse) GetData() []SubscriptionRelationshipsIntroductoryOffersDataInner`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *SubscriptionIntroductoryOffersLinkagesResponse) GetDataOk() (*[]SubscriptionRelationshipsIntroductoryOffersDataInner, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *SubscriptionIntroductoryOffersLinkagesResponse) SetData(v []SubscriptionRelationshipsIntroductoryOffersDataInner)`

SetData sets Data field to given value.


### GetLinks

`func (o *SubscriptionIntroductoryOffersLinkagesResponse) GetLinks() PagedDocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *SubscriptionIntroductoryOffersLinkagesResponse) GetLinksOk() (*PagedDocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *SubscriptionIntroductoryOffersLinkagesResponse) SetLinks(v PagedDocumentLinks)`

SetLinks sets Links field to given value.


### GetMeta

`func (o *SubscriptionIntroductoryOffersLinkagesResponse) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *SubscriptionIntroductoryOffersLinkagesResponse) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *SubscriptionIntroductoryOffersLinkagesResponse) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *SubscriptionIntroductoryOffersLinkagesResponse) HasMeta() bool`

HasMeta returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


