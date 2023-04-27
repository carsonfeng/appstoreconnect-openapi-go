# SubscriptionIntroductoryOfferResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**SubscriptionIntroductoryOffer**](SubscriptionIntroductoryOffer.md) |  | 
**Included** | Pointer to [**[]SubscriptionIntroductoryOffersResponseIncludedInner**](SubscriptionIntroductoryOffersResponseIncludedInner.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewSubscriptionIntroductoryOfferResponse

`func NewSubscriptionIntroductoryOfferResponse(data SubscriptionIntroductoryOffer, links DocumentLinks, ) *SubscriptionIntroductoryOfferResponse`

NewSubscriptionIntroductoryOfferResponse instantiates a new SubscriptionIntroductoryOfferResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionIntroductoryOfferResponseWithDefaults

`func NewSubscriptionIntroductoryOfferResponseWithDefaults() *SubscriptionIntroductoryOfferResponse`

NewSubscriptionIntroductoryOfferResponseWithDefaults instantiates a new SubscriptionIntroductoryOfferResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *SubscriptionIntroductoryOfferResponse) GetData() SubscriptionIntroductoryOffer`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *SubscriptionIntroductoryOfferResponse) GetDataOk() (*SubscriptionIntroductoryOffer, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *SubscriptionIntroductoryOfferResponse) SetData(v SubscriptionIntroductoryOffer)`

SetData sets Data field to given value.


### GetIncluded

`func (o *SubscriptionIntroductoryOfferResponse) GetIncluded() []SubscriptionIntroductoryOffersResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *SubscriptionIntroductoryOfferResponse) GetIncludedOk() (*[]SubscriptionIntroductoryOffersResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *SubscriptionIntroductoryOfferResponse) SetIncluded(v []SubscriptionIntroductoryOffersResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *SubscriptionIntroductoryOfferResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *SubscriptionIntroductoryOfferResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *SubscriptionIntroductoryOfferResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *SubscriptionIntroductoryOfferResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


