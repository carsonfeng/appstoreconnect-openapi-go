# SubscriptionOfferCodeCreateRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**SubscriptionOfferCodeCreateRequestData**](SubscriptionOfferCodeCreateRequestData.md) |  | 
**Included** | Pointer to [**[]SubscriptionOfferCodePriceInlineCreate**](SubscriptionOfferCodePriceInlineCreate.md) |  | [optional] 

## Methods

### NewSubscriptionOfferCodeCreateRequest

`func NewSubscriptionOfferCodeCreateRequest(data SubscriptionOfferCodeCreateRequestData, ) *SubscriptionOfferCodeCreateRequest`

NewSubscriptionOfferCodeCreateRequest instantiates a new SubscriptionOfferCodeCreateRequest object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionOfferCodeCreateRequestWithDefaults

`func NewSubscriptionOfferCodeCreateRequestWithDefaults() *SubscriptionOfferCodeCreateRequest`

NewSubscriptionOfferCodeCreateRequestWithDefaults instantiates a new SubscriptionOfferCodeCreateRequest object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *SubscriptionOfferCodeCreateRequest) GetData() SubscriptionOfferCodeCreateRequestData`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *SubscriptionOfferCodeCreateRequest) GetDataOk() (*SubscriptionOfferCodeCreateRequestData, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *SubscriptionOfferCodeCreateRequest) SetData(v SubscriptionOfferCodeCreateRequestData)`

SetData sets Data field to given value.


### GetIncluded

`func (o *SubscriptionOfferCodeCreateRequest) GetIncluded() []SubscriptionOfferCodePriceInlineCreate`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *SubscriptionOfferCodeCreateRequest) GetIncludedOk() (*[]SubscriptionOfferCodePriceInlineCreate, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *SubscriptionOfferCodeCreateRequest) SetIncluded(v []SubscriptionOfferCodePriceInlineCreate)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *SubscriptionOfferCodeCreateRequest) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


