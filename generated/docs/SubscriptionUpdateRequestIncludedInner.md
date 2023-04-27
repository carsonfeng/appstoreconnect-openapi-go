# SubscriptionUpdateRequestIncludedInner

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | Pointer to **string** |  | [optional] 
**Attributes** | [**SubscriptionIntroductoryOfferInlineCreateAttributes**](SubscriptionIntroductoryOfferInlineCreateAttributes.md) |  | 
**Relationships** | Pointer to [**SubscriptionIntroductoryOfferInlineCreateRelationships**](SubscriptionIntroductoryOfferInlineCreateRelationships.md) |  | [optional] 

## Methods

### NewSubscriptionUpdateRequestIncludedInner

`func NewSubscriptionUpdateRequestIncludedInner(type_ string, attributes SubscriptionIntroductoryOfferInlineCreateAttributes, ) *SubscriptionUpdateRequestIncludedInner`

NewSubscriptionUpdateRequestIncludedInner instantiates a new SubscriptionUpdateRequestIncludedInner object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionUpdateRequestIncludedInnerWithDefaults

`func NewSubscriptionUpdateRequestIncludedInnerWithDefaults() *SubscriptionUpdateRequestIncludedInner`

NewSubscriptionUpdateRequestIncludedInnerWithDefaults instantiates a new SubscriptionUpdateRequestIncludedInner object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *SubscriptionUpdateRequestIncludedInner) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *SubscriptionUpdateRequestIncludedInner) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *SubscriptionUpdateRequestIncludedInner) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *SubscriptionUpdateRequestIncludedInner) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *SubscriptionUpdateRequestIncludedInner) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *SubscriptionUpdateRequestIncludedInner) SetId(v string)`

SetId sets Id field to given value.

### HasId

`func (o *SubscriptionUpdateRequestIncludedInner) HasId() bool`

HasId returns a boolean if a field has been set.

### GetAttributes

`func (o *SubscriptionUpdateRequestIncludedInner) GetAttributes() SubscriptionIntroductoryOfferInlineCreateAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *SubscriptionUpdateRequestIncludedInner) GetAttributesOk() (*SubscriptionIntroductoryOfferInlineCreateAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *SubscriptionUpdateRequestIncludedInner) SetAttributes(v SubscriptionIntroductoryOfferInlineCreateAttributes)`

SetAttributes sets Attributes field to given value.


### GetRelationships

`func (o *SubscriptionUpdateRequestIncludedInner) GetRelationships() SubscriptionIntroductoryOfferInlineCreateRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *SubscriptionUpdateRequestIncludedInner) GetRelationshipsOk() (*SubscriptionIntroductoryOfferInlineCreateRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *SubscriptionUpdateRequestIncludedInner) SetRelationships(v SubscriptionIntroductoryOfferInlineCreateRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *SubscriptionUpdateRequestIncludedInner) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


