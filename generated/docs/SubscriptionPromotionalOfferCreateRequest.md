# SubscriptionPromotionalOfferCreateRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**SubscriptionPromotionalOfferCreateRequestData**](SubscriptionPromotionalOfferCreateRequestData.md) |  | 
**Included** | Pointer to [**[]SubscriptionPromotionalOfferPriceInlineCreate**](SubscriptionPromotionalOfferPriceInlineCreate.md) |  | [optional] 

## Methods

### NewSubscriptionPromotionalOfferCreateRequest

`func NewSubscriptionPromotionalOfferCreateRequest(data SubscriptionPromotionalOfferCreateRequestData, ) *SubscriptionPromotionalOfferCreateRequest`

NewSubscriptionPromotionalOfferCreateRequest instantiates a new SubscriptionPromotionalOfferCreateRequest object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionPromotionalOfferCreateRequestWithDefaults

`func NewSubscriptionPromotionalOfferCreateRequestWithDefaults() *SubscriptionPromotionalOfferCreateRequest`

NewSubscriptionPromotionalOfferCreateRequestWithDefaults instantiates a new SubscriptionPromotionalOfferCreateRequest object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *SubscriptionPromotionalOfferCreateRequest) GetData() SubscriptionPromotionalOfferCreateRequestData`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *SubscriptionPromotionalOfferCreateRequest) GetDataOk() (*SubscriptionPromotionalOfferCreateRequestData, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *SubscriptionPromotionalOfferCreateRequest) SetData(v SubscriptionPromotionalOfferCreateRequestData)`

SetData sets Data field to given value.


### GetIncluded

`func (o *SubscriptionPromotionalOfferCreateRequest) GetIncluded() []SubscriptionPromotionalOfferPriceInlineCreate`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *SubscriptionPromotionalOfferCreateRequest) GetIncludedOk() (*[]SubscriptionPromotionalOfferPriceInlineCreate, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *SubscriptionPromotionalOfferCreateRequest) SetIncluded(v []SubscriptionPromotionalOfferPriceInlineCreate)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *SubscriptionPromotionalOfferCreateRequest) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


