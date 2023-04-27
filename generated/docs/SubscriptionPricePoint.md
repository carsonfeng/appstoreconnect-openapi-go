# SubscriptionPricePoint

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**SubscriptionPricePointAttributes**](SubscriptionPricePointAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**InAppPurchasePricePointRelationships**](InAppPurchasePricePointRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewSubscriptionPricePoint

`func NewSubscriptionPricePoint(type_ string, id string, links ResourceLinks, ) *SubscriptionPricePoint`

NewSubscriptionPricePoint instantiates a new SubscriptionPricePoint object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionPricePointWithDefaults

`func NewSubscriptionPricePointWithDefaults() *SubscriptionPricePoint`

NewSubscriptionPricePointWithDefaults instantiates a new SubscriptionPricePoint object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *SubscriptionPricePoint) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *SubscriptionPricePoint) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *SubscriptionPricePoint) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *SubscriptionPricePoint) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *SubscriptionPricePoint) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *SubscriptionPricePoint) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *SubscriptionPricePoint) GetAttributes() SubscriptionPricePointAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *SubscriptionPricePoint) GetAttributesOk() (*SubscriptionPricePointAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *SubscriptionPricePoint) SetAttributes(v SubscriptionPricePointAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *SubscriptionPricePoint) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *SubscriptionPricePoint) GetRelationships() InAppPurchasePricePointRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *SubscriptionPricePoint) GetRelationshipsOk() (*InAppPurchasePricePointRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *SubscriptionPricePoint) SetRelationships(v InAppPurchasePricePointRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *SubscriptionPricePoint) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *SubscriptionPricePoint) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *SubscriptionPricePoint) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *SubscriptionPricePoint) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


