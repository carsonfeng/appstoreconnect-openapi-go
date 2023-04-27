# SubscriptionIntroductoryOffer

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**SubscriptionIntroductoryOfferAttributes**](SubscriptionIntroductoryOfferAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**SubscriptionIntroductoryOfferRelationships**](SubscriptionIntroductoryOfferRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewSubscriptionIntroductoryOffer

`func NewSubscriptionIntroductoryOffer(type_ string, id string, links ResourceLinks, ) *SubscriptionIntroductoryOffer`

NewSubscriptionIntroductoryOffer instantiates a new SubscriptionIntroductoryOffer object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionIntroductoryOfferWithDefaults

`func NewSubscriptionIntroductoryOfferWithDefaults() *SubscriptionIntroductoryOffer`

NewSubscriptionIntroductoryOfferWithDefaults instantiates a new SubscriptionIntroductoryOffer object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *SubscriptionIntroductoryOffer) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *SubscriptionIntroductoryOffer) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *SubscriptionIntroductoryOffer) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *SubscriptionIntroductoryOffer) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *SubscriptionIntroductoryOffer) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *SubscriptionIntroductoryOffer) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *SubscriptionIntroductoryOffer) GetAttributes() SubscriptionIntroductoryOfferAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *SubscriptionIntroductoryOffer) GetAttributesOk() (*SubscriptionIntroductoryOfferAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *SubscriptionIntroductoryOffer) SetAttributes(v SubscriptionIntroductoryOfferAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *SubscriptionIntroductoryOffer) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *SubscriptionIntroductoryOffer) GetRelationships() SubscriptionIntroductoryOfferRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *SubscriptionIntroductoryOffer) GetRelationshipsOk() (*SubscriptionIntroductoryOfferRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *SubscriptionIntroductoryOffer) SetRelationships(v SubscriptionIntroductoryOfferRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *SubscriptionIntroductoryOffer) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *SubscriptionIntroductoryOffer) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *SubscriptionIntroductoryOffer) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *SubscriptionIntroductoryOffer) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


