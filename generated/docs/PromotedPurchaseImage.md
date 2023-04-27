# PromotedPurchaseImage

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**PromotedPurchaseImageAttributes**](PromotedPurchaseImageAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**PromotedPurchaseImageRelationships**](PromotedPurchaseImageRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewPromotedPurchaseImage

`func NewPromotedPurchaseImage(type_ string, id string, links ResourceLinks, ) *PromotedPurchaseImage`

NewPromotedPurchaseImage instantiates a new PromotedPurchaseImage object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewPromotedPurchaseImageWithDefaults

`func NewPromotedPurchaseImageWithDefaults() *PromotedPurchaseImage`

NewPromotedPurchaseImageWithDefaults instantiates a new PromotedPurchaseImage object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *PromotedPurchaseImage) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *PromotedPurchaseImage) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *PromotedPurchaseImage) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *PromotedPurchaseImage) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *PromotedPurchaseImage) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *PromotedPurchaseImage) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *PromotedPurchaseImage) GetAttributes() PromotedPurchaseImageAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *PromotedPurchaseImage) GetAttributesOk() (*PromotedPurchaseImageAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *PromotedPurchaseImage) SetAttributes(v PromotedPurchaseImageAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *PromotedPurchaseImage) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *PromotedPurchaseImage) GetRelationships() PromotedPurchaseImageRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *PromotedPurchaseImage) GetRelationshipsOk() (*PromotedPurchaseImageRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *PromotedPurchaseImage) SetRelationships(v PromotedPurchaseImageRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *PromotedPurchaseImage) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *PromotedPurchaseImage) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *PromotedPurchaseImage) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *PromotedPurchaseImage) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


