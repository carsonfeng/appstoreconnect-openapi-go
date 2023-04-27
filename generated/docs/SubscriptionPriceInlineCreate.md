# SubscriptionPriceInlineCreate

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | Pointer to **string** |  | [optional] 
**Attributes** | Pointer to [**SubscriptionPriceInlineCreateAttributes**](SubscriptionPriceInlineCreateAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**SubscriptionIntroductoryOfferInlineCreateRelationships**](SubscriptionIntroductoryOfferInlineCreateRelationships.md) |  | [optional] 

## Methods

### NewSubscriptionPriceInlineCreate

`func NewSubscriptionPriceInlineCreate(type_ string, ) *SubscriptionPriceInlineCreate`

NewSubscriptionPriceInlineCreate instantiates a new SubscriptionPriceInlineCreate object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionPriceInlineCreateWithDefaults

`func NewSubscriptionPriceInlineCreateWithDefaults() *SubscriptionPriceInlineCreate`

NewSubscriptionPriceInlineCreateWithDefaults instantiates a new SubscriptionPriceInlineCreate object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *SubscriptionPriceInlineCreate) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *SubscriptionPriceInlineCreate) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *SubscriptionPriceInlineCreate) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *SubscriptionPriceInlineCreate) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *SubscriptionPriceInlineCreate) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *SubscriptionPriceInlineCreate) SetId(v string)`

SetId sets Id field to given value.

### HasId

`func (o *SubscriptionPriceInlineCreate) HasId() bool`

HasId returns a boolean if a field has been set.

### GetAttributes

`func (o *SubscriptionPriceInlineCreate) GetAttributes() SubscriptionPriceInlineCreateAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *SubscriptionPriceInlineCreate) GetAttributesOk() (*SubscriptionPriceInlineCreateAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *SubscriptionPriceInlineCreate) SetAttributes(v SubscriptionPriceInlineCreateAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *SubscriptionPriceInlineCreate) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *SubscriptionPriceInlineCreate) GetRelationships() SubscriptionIntroductoryOfferInlineCreateRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *SubscriptionPriceInlineCreate) GetRelationshipsOk() (*SubscriptionIntroductoryOfferInlineCreateRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *SubscriptionPriceInlineCreate) SetRelationships(v SubscriptionIntroductoryOfferInlineCreateRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *SubscriptionPriceInlineCreate) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


