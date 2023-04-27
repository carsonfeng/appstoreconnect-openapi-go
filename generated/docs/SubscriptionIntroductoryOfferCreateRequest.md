# SubscriptionIntroductoryOfferCreateRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**SubscriptionIntroductoryOfferCreateRequestData**](SubscriptionIntroductoryOfferCreateRequestData.md) |  | 
**Included** | Pointer to [**[]SubscriptionPricePointInlineCreate**](SubscriptionPricePointInlineCreate.md) |  | [optional] 

## Methods

### NewSubscriptionIntroductoryOfferCreateRequest

`func NewSubscriptionIntroductoryOfferCreateRequest(data SubscriptionIntroductoryOfferCreateRequestData, ) *SubscriptionIntroductoryOfferCreateRequest`

NewSubscriptionIntroductoryOfferCreateRequest instantiates a new SubscriptionIntroductoryOfferCreateRequest object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionIntroductoryOfferCreateRequestWithDefaults

`func NewSubscriptionIntroductoryOfferCreateRequestWithDefaults() *SubscriptionIntroductoryOfferCreateRequest`

NewSubscriptionIntroductoryOfferCreateRequestWithDefaults instantiates a new SubscriptionIntroductoryOfferCreateRequest object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *SubscriptionIntroductoryOfferCreateRequest) GetData() SubscriptionIntroductoryOfferCreateRequestData`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *SubscriptionIntroductoryOfferCreateRequest) GetDataOk() (*SubscriptionIntroductoryOfferCreateRequestData, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *SubscriptionIntroductoryOfferCreateRequest) SetData(v SubscriptionIntroductoryOfferCreateRequestData)`

SetData sets Data field to given value.


### GetIncluded

`func (o *SubscriptionIntroductoryOfferCreateRequest) GetIncluded() []SubscriptionPricePointInlineCreate`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *SubscriptionIntroductoryOfferCreateRequest) GetIncludedOk() (*[]SubscriptionPricePointInlineCreate, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *SubscriptionIntroductoryOfferCreateRequest) SetIncluded(v []SubscriptionPricePointInlineCreate)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *SubscriptionIntroductoryOfferCreateRequest) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


