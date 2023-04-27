# SubscriptionPriceCreateRequestDataRelationships

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Subscription** | [**SubscriptionAppStoreReviewScreenshotCreateRequestDataRelationshipsSubscription**](SubscriptionAppStoreReviewScreenshotCreateRequestDataRelationshipsSubscription.md) |  | 
**Territory** | Pointer to [**InAppPurchasePriceScheduleCreateRequestDataRelationshipsBaseTerritory**](InAppPurchasePriceScheduleCreateRequestDataRelationshipsBaseTerritory.md) |  | [optional] 
**SubscriptionPricePoint** | [**SubscriptionPriceCreateRequestDataRelationshipsSubscriptionPricePoint**](SubscriptionPriceCreateRequestDataRelationshipsSubscriptionPricePoint.md) |  | 

## Methods

### NewSubscriptionPriceCreateRequestDataRelationships

`func NewSubscriptionPriceCreateRequestDataRelationships(subscription SubscriptionAppStoreReviewScreenshotCreateRequestDataRelationshipsSubscription, subscriptionPricePoint SubscriptionPriceCreateRequestDataRelationshipsSubscriptionPricePoint, ) *SubscriptionPriceCreateRequestDataRelationships`

NewSubscriptionPriceCreateRequestDataRelationships instantiates a new SubscriptionPriceCreateRequestDataRelationships object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionPriceCreateRequestDataRelationshipsWithDefaults

`func NewSubscriptionPriceCreateRequestDataRelationshipsWithDefaults() *SubscriptionPriceCreateRequestDataRelationships`

NewSubscriptionPriceCreateRequestDataRelationshipsWithDefaults instantiates a new SubscriptionPriceCreateRequestDataRelationships object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetSubscription

`func (o *SubscriptionPriceCreateRequestDataRelationships) GetSubscription() SubscriptionAppStoreReviewScreenshotCreateRequestDataRelationshipsSubscription`

GetSubscription returns the Subscription field if non-nil, zero value otherwise.

### GetSubscriptionOk

`func (o *SubscriptionPriceCreateRequestDataRelationships) GetSubscriptionOk() (*SubscriptionAppStoreReviewScreenshotCreateRequestDataRelationshipsSubscription, bool)`

GetSubscriptionOk returns a tuple with the Subscription field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSubscription

`func (o *SubscriptionPriceCreateRequestDataRelationships) SetSubscription(v SubscriptionAppStoreReviewScreenshotCreateRequestDataRelationshipsSubscription)`

SetSubscription sets Subscription field to given value.


### GetTerritory

`func (o *SubscriptionPriceCreateRequestDataRelationships) GetTerritory() InAppPurchasePriceScheduleCreateRequestDataRelationshipsBaseTerritory`

GetTerritory returns the Territory field if non-nil, zero value otherwise.

### GetTerritoryOk

`func (o *SubscriptionPriceCreateRequestDataRelationships) GetTerritoryOk() (*InAppPurchasePriceScheduleCreateRequestDataRelationshipsBaseTerritory, bool)`

GetTerritoryOk returns a tuple with the Territory field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTerritory

`func (o *SubscriptionPriceCreateRequestDataRelationships) SetTerritory(v InAppPurchasePriceScheduleCreateRequestDataRelationshipsBaseTerritory)`

SetTerritory sets Territory field to given value.

### HasTerritory

`func (o *SubscriptionPriceCreateRequestDataRelationships) HasTerritory() bool`

HasTerritory returns a boolean if a field has been set.

### GetSubscriptionPricePoint

`func (o *SubscriptionPriceCreateRequestDataRelationships) GetSubscriptionPricePoint() SubscriptionPriceCreateRequestDataRelationshipsSubscriptionPricePoint`

GetSubscriptionPricePoint returns the SubscriptionPricePoint field if non-nil, zero value otherwise.

### GetSubscriptionPricePointOk

`func (o *SubscriptionPriceCreateRequestDataRelationships) GetSubscriptionPricePointOk() (*SubscriptionPriceCreateRequestDataRelationshipsSubscriptionPricePoint, bool)`

GetSubscriptionPricePointOk returns a tuple with the SubscriptionPricePoint field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSubscriptionPricePoint

`func (o *SubscriptionPriceCreateRequestDataRelationships) SetSubscriptionPricePoint(v SubscriptionPriceCreateRequestDataRelationshipsSubscriptionPricePoint)`

SetSubscriptionPricePoint sets SubscriptionPricePoint field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


