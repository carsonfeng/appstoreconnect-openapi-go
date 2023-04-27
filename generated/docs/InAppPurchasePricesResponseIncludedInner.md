# InAppPurchasePricesResponseIncludedInner

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**TerritoryAttributes**](TerritoryAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**InAppPurchasePricePointRelationships**](InAppPurchasePricePointRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewInAppPurchasePricesResponseIncludedInner

`func NewInAppPurchasePricesResponseIncludedInner(type_ string, id string, links ResourceLinks, ) *InAppPurchasePricesResponseIncludedInner`

NewInAppPurchasePricesResponseIncludedInner instantiates a new InAppPurchasePricesResponseIncludedInner object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewInAppPurchasePricesResponseIncludedInnerWithDefaults

`func NewInAppPurchasePricesResponseIncludedInnerWithDefaults() *InAppPurchasePricesResponseIncludedInner`

NewInAppPurchasePricesResponseIncludedInnerWithDefaults instantiates a new InAppPurchasePricesResponseIncludedInner object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *InAppPurchasePricesResponseIncludedInner) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *InAppPurchasePricesResponseIncludedInner) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *InAppPurchasePricesResponseIncludedInner) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *InAppPurchasePricesResponseIncludedInner) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *InAppPurchasePricesResponseIncludedInner) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *InAppPurchasePricesResponseIncludedInner) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *InAppPurchasePricesResponseIncludedInner) GetAttributes() TerritoryAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *InAppPurchasePricesResponseIncludedInner) GetAttributesOk() (*TerritoryAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *InAppPurchasePricesResponseIncludedInner) SetAttributes(v TerritoryAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *InAppPurchasePricesResponseIncludedInner) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *InAppPurchasePricesResponseIncludedInner) GetRelationships() InAppPurchasePricePointRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *InAppPurchasePricesResponseIncludedInner) GetRelationshipsOk() (*InAppPurchasePricePointRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *InAppPurchasePricesResponseIncludedInner) SetRelationships(v InAppPurchasePricePointRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *InAppPurchasePricesResponseIncludedInner) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *InAppPurchasePricesResponseIncludedInner) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *InAppPurchasePricesResponseIncludedInner) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *InAppPurchasePricesResponseIncludedInner) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


