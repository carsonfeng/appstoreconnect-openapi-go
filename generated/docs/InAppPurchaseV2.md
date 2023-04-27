# InAppPurchaseV2

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**InAppPurchaseV2Attributes**](InAppPurchaseV2Attributes.md) |  | [optional] 
**Relationships** | Pointer to [**InAppPurchaseV2Relationships**](InAppPurchaseV2Relationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewInAppPurchaseV2

`func NewInAppPurchaseV2(type_ string, id string, links ResourceLinks, ) *InAppPurchaseV2`

NewInAppPurchaseV2 instantiates a new InAppPurchaseV2 object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewInAppPurchaseV2WithDefaults

`func NewInAppPurchaseV2WithDefaults() *InAppPurchaseV2`

NewInAppPurchaseV2WithDefaults instantiates a new InAppPurchaseV2 object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *InAppPurchaseV2) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *InAppPurchaseV2) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *InAppPurchaseV2) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *InAppPurchaseV2) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *InAppPurchaseV2) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *InAppPurchaseV2) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *InAppPurchaseV2) GetAttributes() InAppPurchaseV2Attributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *InAppPurchaseV2) GetAttributesOk() (*InAppPurchaseV2Attributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *InAppPurchaseV2) SetAttributes(v InAppPurchaseV2Attributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *InAppPurchaseV2) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *InAppPurchaseV2) GetRelationships() InAppPurchaseV2Relationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *InAppPurchaseV2) GetRelationshipsOk() (*InAppPurchaseV2Relationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *InAppPurchaseV2) SetRelationships(v InAppPurchaseV2Relationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *InAppPurchaseV2) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *InAppPurchaseV2) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *InAppPurchaseV2) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *InAppPurchaseV2) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


