# SubscriptionRelationships

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**SubscriptionLocalizations** | Pointer to [**SubscriptionRelationshipsSubscriptionLocalizations**](SubscriptionRelationshipsSubscriptionLocalizations.md) |  | [optional] 
**AppStoreReviewScreenshot** | Pointer to [**SubscriptionRelationshipsAppStoreReviewScreenshot**](SubscriptionRelationshipsAppStoreReviewScreenshot.md) |  | [optional] 
**Group** | Pointer to [**SubscriptionGroupLocalizationRelationshipsSubscriptionGroup**](SubscriptionGroupLocalizationRelationshipsSubscriptionGroup.md) |  | [optional] 
**IntroductoryOffers** | Pointer to [**SubscriptionRelationshipsIntroductoryOffers**](SubscriptionRelationshipsIntroductoryOffers.md) |  | [optional] 
**PromotionalOffers** | Pointer to [**SubscriptionRelationshipsPromotionalOffers**](SubscriptionRelationshipsPromotionalOffers.md) |  | [optional] 
**OfferCodes** | Pointer to [**SubscriptionRelationshipsOfferCodes**](SubscriptionRelationshipsOfferCodes.md) |  | [optional] 
**Prices** | Pointer to [**SubscriptionRelationshipsPrices**](SubscriptionRelationshipsPrices.md) |  | [optional] 
**PromotedPurchase** | Pointer to [**InAppPurchaseV2RelationshipsPromotedPurchase**](InAppPurchaseV2RelationshipsPromotedPurchase.md) |  | [optional] 

## Methods

### NewSubscriptionRelationships

`func NewSubscriptionRelationships() *SubscriptionRelationships`

NewSubscriptionRelationships instantiates a new SubscriptionRelationships object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionRelationshipsWithDefaults

`func NewSubscriptionRelationshipsWithDefaults() *SubscriptionRelationships`

NewSubscriptionRelationshipsWithDefaults instantiates a new SubscriptionRelationships object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetSubscriptionLocalizations

`func (o *SubscriptionRelationships) GetSubscriptionLocalizations() SubscriptionRelationshipsSubscriptionLocalizations`

GetSubscriptionLocalizations returns the SubscriptionLocalizations field if non-nil, zero value otherwise.

### GetSubscriptionLocalizationsOk

`func (o *SubscriptionRelationships) GetSubscriptionLocalizationsOk() (*SubscriptionRelationshipsSubscriptionLocalizations, bool)`

GetSubscriptionLocalizationsOk returns a tuple with the SubscriptionLocalizations field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSubscriptionLocalizations

`func (o *SubscriptionRelationships) SetSubscriptionLocalizations(v SubscriptionRelationshipsSubscriptionLocalizations)`

SetSubscriptionLocalizations sets SubscriptionLocalizations field to given value.

### HasSubscriptionLocalizations

`func (o *SubscriptionRelationships) HasSubscriptionLocalizations() bool`

HasSubscriptionLocalizations returns a boolean if a field has been set.

### GetAppStoreReviewScreenshot

`func (o *SubscriptionRelationships) GetAppStoreReviewScreenshot() SubscriptionRelationshipsAppStoreReviewScreenshot`

GetAppStoreReviewScreenshot returns the AppStoreReviewScreenshot field if non-nil, zero value otherwise.

### GetAppStoreReviewScreenshotOk

`func (o *SubscriptionRelationships) GetAppStoreReviewScreenshotOk() (*SubscriptionRelationshipsAppStoreReviewScreenshot, bool)`

GetAppStoreReviewScreenshotOk returns a tuple with the AppStoreReviewScreenshot field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAppStoreReviewScreenshot

`func (o *SubscriptionRelationships) SetAppStoreReviewScreenshot(v SubscriptionRelationshipsAppStoreReviewScreenshot)`

SetAppStoreReviewScreenshot sets AppStoreReviewScreenshot field to given value.

### HasAppStoreReviewScreenshot

`func (o *SubscriptionRelationships) HasAppStoreReviewScreenshot() bool`

HasAppStoreReviewScreenshot returns a boolean if a field has been set.

### GetGroup

`func (o *SubscriptionRelationships) GetGroup() SubscriptionGroupLocalizationRelationshipsSubscriptionGroup`

GetGroup returns the Group field if non-nil, zero value otherwise.

### GetGroupOk

`func (o *SubscriptionRelationships) GetGroupOk() (*SubscriptionGroupLocalizationRelationshipsSubscriptionGroup, bool)`

GetGroupOk returns a tuple with the Group field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetGroup

`func (o *SubscriptionRelationships) SetGroup(v SubscriptionGroupLocalizationRelationshipsSubscriptionGroup)`

SetGroup sets Group field to given value.

### HasGroup

`func (o *SubscriptionRelationships) HasGroup() bool`

HasGroup returns a boolean if a field has been set.

### GetIntroductoryOffers

`func (o *SubscriptionRelationships) GetIntroductoryOffers() SubscriptionRelationshipsIntroductoryOffers`

GetIntroductoryOffers returns the IntroductoryOffers field if non-nil, zero value otherwise.

### GetIntroductoryOffersOk

`func (o *SubscriptionRelationships) GetIntroductoryOffersOk() (*SubscriptionRelationshipsIntroductoryOffers, bool)`

GetIntroductoryOffersOk returns a tuple with the IntroductoryOffers field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIntroductoryOffers

`func (o *SubscriptionRelationships) SetIntroductoryOffers(v SubscriptionRelationshipsIntroductoryOffers)`

SetIntroductoryOffers sets IntroductoryOffers field to given value.

### HasIntroductoryOffers

`func (o *SubscriptionRelationships) HasIntroductoryOffers() bool`

HasIntroductoryOffers returns a boolean if a field has been set.

### GetPromotionalOffers

`func (o *SubscriptionRelationships) GetPromotionalOffers() SubscriptionRelationshipsPromotionalOffers`

GetPromotionalOffers returns the PromotionalOffers field if non-nil, zero value otherwise.

### GetPromotionalOffersOk

`func (o *SubscriptionRelationships) GetPromotionalOffersOk() (*SubscriptionRelationshipsPromotionalOffers, bool)`

GetPromotionalOffersOk returns a tuple with the PromotionalOffers field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPromotionalOffers

`func (o *SubscriptionRelationships) SetPromotionalOffers(v SubscriptionRelationshipsPromotionalOffers)`

SetPromotionalOffers sets PromotionalOffers field to given value.

### HasPromotionalOffers

`func (o *SubscriptionRelationships) HasPromotionalOffers() bool`

HasPromotionalOffers returns a boolean if a field has been set.

### GetOfferCodes

`func (o *SubscriptionRelationships) GetOfferCodes() SubscriptionRelationshipsOfferCodes`

GetOfferCodes returns the OfferCodes field if non-nil, zero value otherwise.

### GetOfferCodesOk

`func (o *SubscriptionRelationships) GetOfferCodesOk() (*SubscriptionRelationshipsOfferCodes, bool)`

GetOfferCodesOk returns a tuple with the OfferCodes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetOfferCodes

`func (o *SubscriptionRelationships) SetOfferCodes(v SubscriptionRelationshipsOfferCodes)`

SetOfferCodes sets OfferCodes field to given value.

### HasOfferCodes

`func (o *SubscriptionRelationships) HasOfferCodes() bool`

HasOfferCodes returns a boolean if a field has been set.

### GetPrices

`func (o *SubscriptionRelationships) GetPrices() SubscriptionRelationshipsPrices`

GetPrices returns the Prices field if non-nil, zero value otherwise.

### GetPricesOk

`func (o *SubscriptionRelationships) GetPricesOk() (*SubscriptionRelationshipsPrices, bool)`

GetPricesOk returns a tuple with the Prices field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPrices

`func (o *SubscriptionRelationships) SetPrices(v SubscriptionRelationshipsPrices)`

SetPrices sets Prices field to given value.

### HasPrices

`func (o *SubscriptionRelationships) HasPrices() bool`

HasPrices returns a boolean if a field has been set.

### GetPromotedPurchase

`func (o *SubscriptionRelationships) GetPromotedPurchase() InAppPurchaseV2RelationshipsPromotedPurchase`

GetPromotedPurchase returns the PromotedPurchase field if non-nil, zero value otherwise.

### GetPromotedPurchaseOk

`func (o *SubscriptionRelationships) GetPromotedPurchaseOk() (*InAppPurchaseV2RelationshipsPromotedPurchase, bool)`

GetPromotedPurchaseOk returns a tuple with the PromotedPurchase field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPromotedPurchase

`func (o *SubscriptionRelationships) SetPromotedPurchase(v InAppPurchaseV2RelationshipsPromotedPurchase)`

SetPromotedPurchase sets PromotedPurchase field to given value.

### HasPromotedPurchase

`func (o *SubscriptionRelationships) HasPromotedPurchase() bool`

HasPromotedPurchase returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


