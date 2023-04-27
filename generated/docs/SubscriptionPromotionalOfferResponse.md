# SubscriptionPromotionalOfferResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**SubscriptionPromotionalOffer**](SubscriptionPromotionalOffer.md) |  | 
**Included** | Pointer to [**[]SubscriptionPromotionalOffersResponseIncludedInner**](SubscriptionPromotionalOffersResponseIncludedInner.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewSubscriptionPromotionalOfferResponse

`func NewSubscriptionPromotionalOfferResponse(data SubscriptionPromotionalOffer, links DocumentLinks, ) *SubscriptionPromotionalOfferResponse`

NewSubscriptionPromotionalOfferResponse instantiates a new SubscriptionPromotionalOfferResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionPromotionalOfferResponseWithDefaults

`func NewSubscriptionPromotionalOfferResponseWithDefaults() *SubscriptionPromotionalOfferResponse`

NewSubscriptionPromotionalOfferResponseWithDefaults instantiates a new SubscriptionPromotionalOfferResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *SubscriptionPromotionalOfferResponse) GetData() SubscriptionPromotionalOffer`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *SubscriptionPromotionalOfferResponse) GetDataOk() (*SubscriptionPromotionalOffer, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *SubscriptionPromotionalOfferResponse) SetData(v SubscriptionPromotionalOffer)`

SetData sets Data field to given value.


### GetIncluded

`func (o *SubscriptionPromotionalOfferResponse) GetIncluded() []SubscriptionPromotionalOffersResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *SubscriptionPromotionalOfferResponse) GetIncludedOk() (*[]SubscriptionPromotionalOffersResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *SubscriptionPromotionalOfferResponse) SetIncluded(v []SubscriptionPromotionalOffersResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *SubscriptionPromotionalOfferResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *SubscriptionPromotionalOfferResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *SubscriptionPromotionalOfferResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *SubscriptionPromotionalOfferResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


