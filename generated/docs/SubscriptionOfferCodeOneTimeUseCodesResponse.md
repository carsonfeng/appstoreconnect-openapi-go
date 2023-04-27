# SubscriptionOfferCodeOneTimeUseCodesResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**[]SubscriptionOfferCodeOneTimeUseCode**](SubscriptionOfferCodeOneTimeUseCode.md) |  | 
**Included** | Pointer to [**[]SubscriptionOfferCode**](SubscriptionOfferCode.md) |  | [optional] 
**Links** | [**PagedDocumentLinks**](PagedDocumentLinks.md) |  | 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 

## Methods

### NewSubscriptionOfferCodeOneTimeUseCodesResponse

`func NewSubscriptionOfferCodeOneTimeUseCodesResponse(data []SubscriptionOfferCodeOneTimeUseCode, links PagedDocumentLinks, ) *SubscriptionOfferCodeOneTimeUseCodesResponse`

NewSubscriptionOfferCodeOneTimeUseCodesResponse instantiates a new SubscriptionOfferCodeOneTimeUseCodesResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionOfferCodeOneTimeUseCodesResponseWithDefaults

`func NewSubscriptionOfferCodeOneTimeUseCodesResponseWithDefaults() *SubscriptionOfferCodeOneTimeUseCodesResponse`

NewSubscriptionOfferCodeOneTimeUseCodesResponseWithDefaults instantiates a new SubscriptionOfferCodeOneTimeUseCodesResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *SubscriptionOfferCodeOneTimeUseCodesResponse) GetData() []SubscriptionOfferCodeOneTimeUseCode`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *SubscriptionOfferCodeOneTimeUseCodesResponse) GetDataOk() (*[]SubscriptionOfferCodeOneTimeUseCode, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *SubscriptionOfferCodeOneTimeUseCodesResponse) SetData(v []SubscriptionOfferCodeOneTimeUseCode)`

SetData sets Data field to given value.


### GetIncluded

`func (o *SubscriptionOfferCodeOneTimeUseCodesResponse) GetIncluded() []SubscriptionOfferCode`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *SubscriptionOfferCodeOneTimeUseCodesResponse) GetIncludedOk() (*[]SubscriptionOfferCode, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *SubscriptionOfferCodeOneTimeUseCodesResponse) SetIncluded(v []SubscriptionOfferCode)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *SubscriptionOfferCodeOneTimeUseCodesResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *SubscriptionOfferCodeOneTimeUseCodesResponse) GetLinks() PagedDocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *SubscriptionOfferCodeOneTimeUseCodesResponse) GetLinksOk() (*PagedDocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *SubscriptionOfferCodeOneTimeUseCodesResponse) SetLinks(v PagedDocumentLinks)`

SetLinks sets Links field to given value.


### GetMeta

`func (o *SubscriptionOfferCodeOneTimeUseCodesResponse) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *SubscriptionOfferCodeOneTimeUseCodesResponse) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *SubscriptionOfferCodeOneTimeUseCodesResponse) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *SubscriptionOfferCodeOneTimeUseCodesResponse) HasMeta() bool`

HasMeta returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


