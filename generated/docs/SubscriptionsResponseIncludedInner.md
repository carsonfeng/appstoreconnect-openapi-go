# SubscriptionsResponseIncludedInner

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**PromotedPurchaseAttributes**](PromotedPurchaseAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**PromotedPurchaseRelationships**](PromotedPurchaseRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewSubscriptionsResponseIncludedInner

`func NewSubscriptionsResponseIncludedInner(type_ string, id string, links ResourceLinks, ) *SubscriptionsResponseIncludedInner`

NewSubscriptionsResponseIncludedInner instantiates a new SubscriptionsResponseIncludedInner object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionsResponseIncludedInnerWithDefaults

`func NewSubscriptionsResponseIncludedInnerWithDefaults() *SubscriptionsResponseIncludedInner`

NewSubscriptionsResponseIncludedInnerWithDefaults instantiates a new SubscriptionsResponseIncludedInner object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *SubscriptionsResponseIncludedInner) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *SubscriptionsResponseIncludedInner) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *SubscriptionsResponseIncludedInner) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *SubscriptionsResponseIncludedInner) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *SubscriptionsResponseIncludedInner) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *SubscriptionsResponseIncludedInner) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *SubscriptionsResponseIncludedInner) GetAttributes() PromotedPurchaseAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *SubscriptionsResponseIncludedInner) GetAttributesOk() (*PromotedPurchaseAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *SubscriptionsResponseIncludedInner) SetAttributes(v PromotedPurchaseAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *SubscriptionsResponseIncludedInner) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *SubscriptionsResponseIncludedInner) GetRelationships() PromotedPurchaseRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *SubscriptionsResponseIncludedInner) GetRelationshipsOk() (*PromotedPurchaseRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *SubscriptionsResponseIncludedInner) SetRelationships(v PromotedPurchaseRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *SubscriptionsResponseIncludedInner) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *SubscriptionsResponseIncludedInner) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *SubscriptionsResponseIncludedInner) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *SubscriptionsResponseIncludedInner) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


