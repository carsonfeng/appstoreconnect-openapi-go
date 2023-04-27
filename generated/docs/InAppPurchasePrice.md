# InAppPurchasePrice

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**InAppPurchasePriceAttributes**](InAppPurchasePriceAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**InAppPurchasePriceRelationships**](InAppPurchasePriceRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewInAppPurchasePrice

`func NewInAppPurchasePrice(type_ string, id string, links ResourceLinks, ) *InAppPurchasePrice`

NewInAppPurchasePrice instantiates a new InAppPurchasePrice object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewInAppPurchasePriceWithDefaults

`func NewInAppPurchasePriceWithDefaults() *InAppPurchasePrice`

NewInAppPurchasePriceWithDefaults instantiates a new InAppPurchasePrice object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *InAppPurchasePrice) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *InAppPurchasePrice) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *InAppPurchasePrice) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *InAppPurchasePrice) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *InAppPurchasePrice) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *InAppPurchasePrice) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *InAppPurchasePrice) GetAttributes() InAppPurchasePriceAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *InAppPurchasePrice) GetAttributesOk() (*InAppPurchasePriceAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *InAppPurchasePrice) SetAttributes(v InAppPurchasePriceAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *InAppPurchasePrice) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *InAppPurchasePrice) GetRelationships() InAppPurchasePriceRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *InAppPurchasePrice) GetRelationshipsOk() (*InAppPurchasePriceRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *InAppPurchasePrice) SetRelationships(v InAppPurchasePriceRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *InAppPurchasePrice) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *InAppPurchasePrice) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *InAppPurchasePrice) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *InAppPurchasePrice) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


