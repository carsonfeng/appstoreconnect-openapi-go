# SubscriptionPromotionalOffersResponseIncludedInner

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**SubscriptionAttributes**](SubscriptionAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**SubscriptionOfferCodePriceRelationships**](SubscriptionOfferCodePriceRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewSubscriptionPromotionalOffersResponseIncludedInner

`func NewSubscriptionPromotionalOffersResponseIncludedInner(type_ string, id string, links ResourceLinks, ) *SubscriptionPromotionalOffersResponseIncludedInner`

NewSubscriptionPromotionalOffersResponseIncludedInner instantiates a new SubscriptionPromotionalOffersResponseIncludedInner object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionPromotionalOffersResponseIncludedInnerWithDefaults

`func NewSubscriptionPromotionalOffersResponseIncludedInnerWithDefaults() *SubscriptionPromotionalOffersResponseIncludedInner`

NewSubscriptionPromotionalOffersResponseIncludedInnerWithDefaults instantiates a new SubscriptionPromotionalOffersResponseIncludedInner object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *SubscriptionPromotionalOffersResponseIncludedInner) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *SubscriptionPromotionalOffersResponseIncludedInner) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *SubscriptionPromotionalOffersResponseIncludedInner) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *SubscriptionPromotionalOffersResponseIncludedInner) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *SubscriptionPromotionalOffersResponseIncludedInner) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *SubscriptionPromotionalOffersResponseIncludedInner) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *SubscriptionPromotionalOffersResponseIncludedInner) GetAttributes() SubscriptionAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *SubscriptionPromotionalOffersResponseIncludedInner) GetAttributesOk() (*SubscriptionAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *SubscriptionPromotionalOffersResponseIncludedInner) SetAttributes(v SubscriptionAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *SubscriptionPromotionalOffersResponseIncludedInner) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *SubscriptionPromotionalOffersResponseIncludedInner) GetRelationships() SubscriptionOfferCodePriceRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *SubscriptionPromotionalOffersResponseIncludedInner) GetRelationshipsOk() (*SubscriptionOfferCodePriceRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *SubscriptionPromotionalOffersResponseIncludedInner) SetRelationships(v SubscriptionOfferCodePriceRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *SubscriptionPromotionalOffersResponseIncludedInner) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *SubscriptionPromotionalOffersResponseIncludedInner) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *SubscriptionPromotionalOffersResponseIncludedInner) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *SubscriptionPromotionalOffersResponseIncludedInner) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


