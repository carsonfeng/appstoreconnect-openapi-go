# InAppPurchasePricePoint

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**InAppPurchasePricePointAttributes**](InAppPurchasePricePointAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**InAppPurchasePricePointRelationships**](InAppPurchasePricePointRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewInAppPurchasePricePoint

`func NewInAppPurchasePricePoint(type_ string, id string, links ResourceLinks, ) *InAppPurchasePricePoint`

NewInAppPurchasePricePoint instantiates a new InAppPurchasePricePoint object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewInAppPurchasePricePointWithDefaults

`func NewInAppPurchasePricePointWithDefaults() *InAppPurchasePricePoint`

NewInAppPurchasePricePointWithDefaults instantiates a new InAppPurchasePricePoint object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *InAppPurchasePricePoint) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *InAppPurchasePricePoint) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *InAppPurchasePricePoint) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *InAppPurchasePricePoint) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *InAppPurchasePricePoint) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *InAppPurchasePricePoint) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *InAppPurchasePricePoint) GetAttributes() InAppPurchasePricePointAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *InAppPurchasePricePoint) GetAttributesOk() (*InAppPurchasePricePointAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *InAppPurchasePricePoint) SetAttributes(v InAppPurchasePricePointAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *InAppPurchasePricePoint) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *InAppPurchasePricePoint) GetRelationships() InAppPurchasePricePointRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *InAppPurchasePricePoint) GetRelationshipsOk() (*InAppPurchasePricePointRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *InAppPurchasePricePoint) SetRelationships(v InAppPurchasePricePointRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *InAppPurchasePricePoint) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *InAppPurchasePricePoint) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *InAppPurchasePricePoint) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *InAppPurchasePricePoint) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


