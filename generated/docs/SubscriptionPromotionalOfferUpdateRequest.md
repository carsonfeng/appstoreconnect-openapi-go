# SubscriptionPromotionalOfferUpdateRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**SubscriptionPromotionalOfferUpdateRequestData**](SubscriptionPromotionalOfferUpdateRequestData.md) |  | 
**Included** | Pointer to [**[]SubscriptionPromotionalOfferPriceInlineCreate**](SubscriptionPromotionalOfferPriceInlineCreate.md) |  | [optional] 

## Methods

### NewSubscriptionPromotionalOfferUpdateRequest

`func NewSubscriptionPromotionalOfferUpdateRequest(data SubscriptionPromotionalOfferUpdateRequestData, ) *SubscriptionPromotionalOfferUpdateRequest`

NewSubscriptionPromotionalOfferUpdateRequest instantiates a new SubscriptionPromotionalOfferUpdateRequest object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionPromotionalOfferUpdateRequestWithDefaults

`func NewSubscriptionPromotionalOfferUpdateRequestWithDefaults() *SubscriptionPromotionalOfferUpdateRequest`

NewSubscriptionPromotionalOfferUpdateRequestWithDefaults instantiates a new SubscriptionPromotionalOfferUpdateRequest object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *SubscriptionPromotionalOfferUpdateRequest) GetData() SubscriptionPromotionalOfferUpdateRequestData`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *SubscriptionPromotionalOfferUpdateRequest) GetDataOk() (*SubscriptionPromotionalOfferUpdateRequestData, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *SubscriptionPromotionalOfferUpdateRequest) SetData(v SubscriptionPromotionalOfferUpdateRequestData)`

SetData sets Data field to given value.


### GetIncluded

`func (o *SubscriptionPromotionalOfferUpdateRequest) GetIncluded() []SubscriptionPromotionalOfferPriceInlineCreate`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *SubscriptionPromotionalOfferUpdateRequest) GetIncludedOk() (*[]SubscriptionPromotionalOfferPriceInlineCreate, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *SubscriptionPromotionalOfferUpdateRequest) SetIncluded(v []SubscriptionPromotionalOfferPriceInlineCreate)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *SubscriptionPromotionalOfferUpdateRequest) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


