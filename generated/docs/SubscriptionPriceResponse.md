# SubscriptionPriceResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**SubscriptionPrice**](SubscriptionPrice.md) |  | 
**Included** | Pointer to [**[]SubscriptionOfferCodePricesResponseIncludedInner**](SubscriptionOfferCodePricesResponseIncludedInner.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewSubscriptionPriceResponse

`func NewSubscriptionPriceResponse(data SubscriptionPrice, links DocumentLinks, ) *SubscriptionPriceResponse`

NewSubscriptionPriceResponse instantiates a new SubscriptionPriceResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionPriceResponseWithDefaults

`func NewSubscriptionPriceResponseWithDefaults() *SubscriptionPriceResponse`

NewSubscriptionPriceResponseWithDefaults instantiates a new SubscriptionPriceResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *SubscriptionPriceResponse) GetData() SubscriptionPrice`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *SubscriptionPriceResponse) GetDataOk() (*SubscriptionPrice, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *SubscriptionPriceResponse) SetData(v SubscriptionPrice)`

SetData sets Data field to given value.


### GetIncluded

`func (o *SubscriptionPriceResponse) GetIncluded() []SubscriptionOfferCodePricesResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *SubscriptionPriceResponse) GetIncludedOk() (*[]SubscriptionOfferCodePricesResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *SubscriptionPriceResponse) SetIncluded(v []SubscriptionOfferCodePricesResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *SubscriptionPriceResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *SubscriptionPriceResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *SubscriptionPriceResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *SubscriptionPriceResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


