# SubscriptionOfferCodeRelationships

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Subscription** | Pointer to [**PromotedPurchaseRelationshipsSubscription**](PromotedPurchaseRelationshipsSubscription.md) |  | [optional] 
**OneTimeUseCodes** | Pointer to [**SubscriptionOfferCodeRelationshipsOneTimeUseCodes**](SubscriptionOfferCodeRelationshipsOneTimeUseCodes.md) |  | [optional] 
**CustomCodes** | Pointer to [**SubscriptionOfferCodeRelationshipsCustomCodes**](SubscriptionOfferCodeRelationshipsCustomCodes.md) |  | [optional] 
**Prices** | Pointer to [**SubscriptionOfferCodeRelationshipsPrices**](SubscriptionOfferCodeRelationshipsPrices.md) |  | [optional] 

## Methods

### NewSubscriptionOfferCodeRelationships

`func NewSubscriptionOfferCodeRelationships() *SubscriptionOfferCodeRelationships`

NewSubscriptionOfferCodeRelationships instantiates a new SubscriptionOfferCodeRelationships object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionOfferCodeRelationshipsWithDefaults

`func NewSubscriptionOfferCodeRelationshipsWithDefaults() *SubscriptionOfferCodeRelationships`

NewSubscriptionOfferCodeRelationshipsWithDefaults instantiates a new SubscriptionOfferCodeRelationships object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetSubscription

`func (o *SubscriptionOfferCodeRelationships) GetSubscription() PromotedPurchaseRelationshipsSubscription`

GetSubscription returns the Subscription field if non-nil, zero value otherwise.

### GetSubscriptionOk

`func (o *SubscriptionOfferCodeRelationships) GetSubscriptionOk() (*PromotedPurchaseRelationshipsSubscription, bool)`

GetSubscriptionOk returns a tuple with the Subscription field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSubscription

`func (o *SubscriptionOfferCodeRelationships) SetSubscription(v PromotedPurchaseRelationshipsSubscription)`

SetSubscription sets Subscription field to given value.

### HasSubscription

`func (o *SubscriptionOfferCodeRelationships) HasSubscription() bool`

HasSubscription returns a boolean if a field has been set.

### GetOneTimeUseCodes

`func (o *SubscriptionOfferCodeRelationships) GetOneTimeUseCodes() SubscriptionOfferCodeRelationshipsOneTimeUseCodes`

GetOneTimeUseCodes returns the OneTimeUseCodes field if non-nil, zero value otherwise.

### GetOneTimeUseCodesOk

`func (o *SubscriptionOfferCodeRelationships) GetOneTimeUseCodesOk() (*SubscriptionOfferCodeRelationshipsOneTimeUseCodes, bool)`

GetOneTimeUseCodesOk returns a tuple with the OneTimeUseCodes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetOneTimeUseCodes

`func (o *SubscriptionOfferCodeRelationships) SetOneTimeUseCodes(v SubscriptionOfferCodeRelationshipsOneTimeUseCodes)`

SetOneTimeUseCodes sets OneTimeUseCodes field to given value.

### HasOneTimeUseCodes

`func (o *SubscriptionOfferCodeRelationships) HasOneTimeUseCodes() bool`

HasOneTimeUseCodes returns a boolean if a field has been set.

### GetCustomCodes

`func (o *SubscriptionOfferCodeRelationships) GetCustomCodes() SubscriptionOfferCodeRelationshipsCustomCodes`

GetCustomCodes returns the CustomCodes field if non-nil, zero value otherwise.

### GetCustomCodesOk

`func (o *SubscriptionOfferCodeRelationships) GetCustomCodesOk() (*SubscriptionOfferCodeRelationshipsCustomCodes, bool)`

GetCustomCodesOk returns a tuple with the CustomCodes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCustomCodes

`func (o *SubscriptionOfferCodeRelationships) SetCustomCodes(v SubscriptionOfferCodeRelationshipsCustomCodes)`

SetCustomCodes sets CustomCodes field to given value.

### HasCustomCodes

`func (o *SubscriptionOfferCodeRelationships) HasCustomCodes() bool`

HasCustomCodes returns a boolean if a field has been set.

### GetPrices

`func (o *SubscriptionOfferCodeRelationships) GetPrices() SubscriptionOfferCodeRelationshipsPrices`

GetPrices returns the Prices field if non-nil, zero value otherwise.

### GetPricesOk

`func (o *SubscriptionOfferCodeRelationships) GetPricesOk() (*SubscriptionOfferCodeRelationshipsPrices, bool)`

GetPricesOk returns a tuple with the Prices field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPrices

`func (o *SubscriptionOfferCodeRelationships) SetPrices(v SubscriptionOfferCodeRelationshipsPrices)`

SetPrices sets Prices field to given value.

### HasPrices

`func (o *SubscriptionOfferCodeRelationships) HasPrices() bool`

HasPrices returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


