# SubscriptionIntroductoryOffersResponseIncludedInner

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**SubscriptionPricePointAttributes**](SubscriptionPricePointAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**InAppPurchasePricePointRelationships**](InAppPurchasePricePointRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewSubscriptionIntroductoryOffersResponseIncludedInner

`func NewSubscriptionIntroductoryOffersResponseIncludedInner(type_ string, id string, links ResourceLinks, ) *SubscriptionIntroductoryOffersResponseIncludedInner`

NewSubscriptionIntroductoryOffersResponseIncludedInner instantiates a new SubscriptionIntroductoryOffersResponseIncludedInner object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionIntroductoryOffersResponseIncludedInnerWithDefaults

`func NewSubscriptionIntroductoryOffersResponseIncludedInnerWithDefaults() *SubscriptionIntroductoryOffersResponseIncludedInner`

NewSubscriptionIntroductoryOffersResponseIncludedInnerWithDefaults instantiates a new SubscriptionIntroductoryOffersResponseIncludedInner object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *SubscriptionIntroductoryOffersResponseIncludedInner) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *SubscriptionIntroductoryOffersResponseIncludedInner) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *SubscriptionIntroductoryOffersResponseIncludedInner) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *SubscriptionIntroductoryOffersResponseIncludedInner) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *SubscriptionIntroductoryOffersResponseIncludedInner) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *SubscriptionIntroductoryOffersResponseIncludedInner) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *SubscriptionIntroductoryOffersResponseIncludedInner) GetAttributes() SubscriptionPricePointAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *SubscriptionIntroductoryOffersResponseIncludedInner) GetAttributesOk() (*SubscriptionPricePointAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *SubscriptionIntroductoryOffersResponseIncludedInner) SetAttributes(v SubscriptionPricePointAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *SubscriptionIntroductoryOffersResponseIncludedInner) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *SubscriptionIntroductoryOffersResponseIncludedInner) GetRelationships() InAppPurchasePricePointRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *SubscriptionIntroductoryOffersResponseIncludedInner) GetRelationshipsOk() (*InAppPurchasePricePointRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *SubscriptionIntroductoryOffersResponseIncludedInner) SetRelationships(v InAppPurchasePricePointRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *SubscriptionIntroductoryOffersResponseIncludedInner) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *SubscriptionIntroductoryOffersResponseIncludedInner) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *SubscriptionIntroductoryOffersResponseIncludedInner) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *SubscriptionIntroductoryOffersResponseIncludedInner) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


