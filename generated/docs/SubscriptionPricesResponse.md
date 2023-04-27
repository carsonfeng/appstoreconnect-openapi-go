# SubscriptionPricesResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**[]SubscriptionPrice**](SubscriptionPrice.md) |  | 
**Included** | Pointer to [**[]SubscriptionOfferCodePricesResponseIncludedInner**](SubscriptionOfferCodePricesResponseIncludedInner.md) |  | [optional] 
**Links** | [**PagedDocumentLinks**](PagedDocumentLinks.md) |  | 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 

## Methods

### NewSubscriptionPricesResponse

`func NewSubscriptionPricesResponse(data []SubscriptionPrice, links PagedDocumentLinks, ) *SubscriptionPricesResponse`

NewSubscriptionPricesResponse instantiates a new SubscriptionPricesResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionPricesResponseWithDefaults

`func NewSubscriptionPricesResponseWithDefaults() *SubscriptionPricesResponse`

NewSubscriptionPricesResponseWithDefaults instantiates a new SubscriptionPricesResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *SubscriptionPricesResponse) GetData() []SubscriptionPrice`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *SubscriptionPricesResponse) GetDataOk() (*[]SubscriptionPrice, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *SubscriptionPricesResponse) SetData(v []SubscriptionPrice)`

SetData sets Data field to given value.


### GetIncluded

`func (o *SubscriptionPricesResponse) GetIncluded() []SubscriptionOfferCodePricesResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *SubscriptionPricesResponse) GetIncludedOk() (*[]SubscriptionOfferCodePricesResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *SubscriptionPricesResponse) SetIncluded(v []SubscriptionOfferCodePricesResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *SubscriptionPricesResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *SubscriptionPricesResponse) GetLinks() PagedDocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *SubscriptionPricesResponse) GetLinksOk() (*PagedDocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *SubscriptionPricesResponse) SetLinks(v PagedDocumentLinks)`

SetLinks sets Links field to given value.


### GetMeta

`func (o *SubscriptionPricesResponse) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *SubscriptionPricesResponse) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *SubscriptionPricesResponse) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *SubscriptionPricesResponse) HasMeta() bool`

HasMeta returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


