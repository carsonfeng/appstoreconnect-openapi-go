# SubscriptionPromotionalOffer

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**SubscriptionPromotionalOfferAttributes**](SubscriptionPromotionalOfferAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**SubscriptionPromotionalOfferRelationships**](SubscriptionPromotionalOfferRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewSubscriptionPromotionalOffer

`func NewSubscriptionPromotionalOffer(type_ string, id string, links ResourceLinks, ) *SubscriptionPromotionalOffer`

NewSubscriptionPromotionalOffer instantiates a new SubscriptionPromotionalOffer object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionPromotionalOfferWithDefaults

`func NewSubscriptionPromotionalOfferWithDefaults() *SubscriptionPromotionalOffer`

NewSubscriptionPromotionalOfferWithDefaults instantiates a new SubscriptionPromotionalOffer object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *SubscriptionPromotionalOffer) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *SubscriptionPromotionalOffer) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *SubscriptionPromotionalOffer) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *SubscriptionPromotionalOffer) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *SubscriptionPromotionalOffer) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *SubscriptionPromotionalOffer) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *SubscriptionPromotionalOffer) GetAttributes() SubscriptionPromotionalOfferAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *SubscriptionPromotionalOffer) GetAttributesOk() (*SubscriptionPromotionalOfferAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *SubscriptionPromotionalOffer) SetAttributes(v SubscriptionPromotionalOfferAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *SubscriptionPromotionalOffer) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *SubscriptionPromotionalOffer) GetRelationships() SubscriptionPromotionalOfferRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *SubscriptionPromotionalOffer) GetRelationshipsOk() (*SubscriptionPromotionalOfferRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *SubscriptionPromotionalOffer) SetRelationships(v SubscriptionPromotionalOfferRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *SubscriptionPromotionalOffer) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *SubscriptionPromotionalOffer) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *SubscriptionPromotionalOffer) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *SubscriptionPromotionalOffer) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


