# SubscriptionOfferCodeCustomCodesResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**[]SubscriptionOfferCodeCustomCode**](SubscriptionOfferCodeCustomCode.md) |  | 
**Included** | Pointer to [**[]SubscriptionOfferCode**](SubscriptionOfferCode.md) |  | [optional] 
**Links** | [**PagedDocumentLinks**](PagedDocumentLinks.md) |  | 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 

## Methods

### NewSubscriptionOfferCodeCustomCodesResponse

`func NewSubscriptionOfferCodeCustomCodesResponse(data []SubscriptionOfferCodeCustomCode, links PagedDocumentLinks, ) *SubscriptionOfferCodeCustomCodesResponse`

NewSubscriptionOfferCodeCustomCodesResponse instantiates a new SubscriptionOfferCodeCustomCodesResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionOfferCodeCustomCodesResponseWithDefaults

`func NewSubscriptionOfferCodeCustomCodesResponseWithDefaults() *SubscriptionOfferCodeCustomCodesResponse`

NewSubscriptionOfferCodeCustomCodesResponseWithDefaults instantiates a new SubscriptionOfferCodeCustomCodesResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *SubscriptionOfferCodeCustomCodesResponse) GetData() []SubscriptionOfferCodeCustomCode`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *SubscriptionOfferCodeCustomCodesResponse) GetDataOk() (*[]SubscriptionOfferCodeCustomCode, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *SubscriptionOfferCodeCustomCodesResponse) SetData(v []SubscriptionOfferCodeCustomCode)`

SetData sets Data field to given value.


### GetIncluded

`func (o *SubscriptionOfferCodeCustomCodesResponse) GetIncluded() []SubscriptionOfferCode`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *SubscriptionOfferCodeCustomCodesResponse) GetIncludedOk() (*[]SubscriptionOfferCode, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *SubscriptionOfferCodeCustomCodesResponse) SetIncluded(v []SubscriptionOfferCode)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *SubscriptionOfferCodeCustomCodesResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *SubscriptionOfferCodeCustomCodesResponse) GetLinks() PagedDocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *SubscriptionOfferCodeCustomCodesResponse) GetLinksOk() (*PagedDocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *SubscriptionOfferCodeCustomCodesResponse) SetLinks(v PagedDocumentLinks)`

SetLinks sets Links field to given value.


### GetMeta

`func (o *SubscriptionOfferCodeCustomCodesResponse) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *SubscriptionOfferCodeCustomCodesResponse) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *SubscriptionOfferCodeCustomCodesResponse) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *SubscriptionOfferCodeCustomCodesResponse) HasMeta() bool`

HasMeta returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


