# SubscriptionPromotionalOfferPricesResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**[]SubscriptionPromotionalOfferPrice**](SubscriptionPromotionalOfferPrice.md) |  | 
**Included** | Pointer to [**[]SubscriptionOfferCodePricesResponseIncludedInner**](SubscriptionOfferCodePricesResponseIncludedInner.md) |  | [optional] 
**Links** | [**PagedDocumentLinks**](PagedDocumentLinks.md) |  | 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 

## Methods

### NewSubscriptionPromotionalOfferPricesResponse

`func NewSubscriptionPromotionalOfferPricesResponse(data []SubscriptionPromotionalOfferPrice, links PagedDocumentLinks, ) *SubscriptionPromotionalOfferPricesResponse`

NewSubscriptionPromotionalOfferPricesResponse instantiates a new SubscriptionPromotionalOfferPricesResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionPromotionalOfferPricesResponseWithDefaults

`func NewSubscriptionPromotionalOfferPricesResponseWithDefaults() *SubscriptionPromotionalOfferPricesResponse`

NewSubscriptionPromotionalOfferPricesResponseWithDefaults instantiates a new SubscriptionPromotionalOfferPricesResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *SubscriptionPromotionalOfferPricesResponse) GetData() []SubscriptionPromotionalOfferPrice`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *SubscriptionPromotionalOfferPricesResponse) GetDataOk() (*[]SubscriptionPromotionalOfferPrice, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *SubscriptionPromotionalOfferPricesResponse) SetData(v []SubscriptionPromotionalOfferPrice)`

SetData sets Data field to given value.


### GetIncluded

`func (o *SubscriptionPromotionalOfferPricesResponse) GetIncluded() []SubscriptionOfferCodePricesResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *SubscriptionPromotionalOfferPricesResponse) GetIncludedOk() (*[]SubscriptionOfferCodePricesResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *SubscriptionPromotionalOfferPricesResponse) SetIncluded(v []SubscriptionOfferCodePricesResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *SubscriptionPromotionalOfferPricesResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *SubscriptionPromotionalOfferPricesResponse) GetLinks() PagedDocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *SubscriptionPromotionalOfferPricesResponse) GetLinksOk() (*PagedDocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *SubscriptionPromotionalOfferPricesResponse) SetLinks(v PagedDocumentLinks)`

SetLinks sets Links field to given value.


### GetMeta

`func (o *SubscriptionPromotionalOfferPricesResponse) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *SubscriptionPromotionalOfferPricesResponse) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *SubscriptionPromotionalOfferPricesResponse) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *SubscriptionPromotionalOfferPricesResponse) HasMeta() bool`

HasMeta returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


