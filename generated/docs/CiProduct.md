# CiProduct

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**CiProductAttributes**](CiProductAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**CiProductRelationships**](CiProductRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewCiProduct

`func NewCiProduct(type_ string, id string, links ResourceLinks, ) *CiProduct`

NewCiProduct instantiates a new CiProduct object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCiProductWithDefaults

`func NewCiProductWithDefaults() *CiProduct`

NewCiProductWithDefaults instantiates a new CiProduct object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *CiProduct) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *CiProduct) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *CiProduct) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *CiProduct) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *CiProduct) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *CiProduct) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *CiProduct) GetAttributes() CiProductAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *CiProduct) GetAttributesOk() (*CiProductAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *CiProduct) SetAttributes(v CiProductAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *CiProduct) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *CiProduct) GetRelationships() CiProductRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *CiProduct) GetRelationshipsOk() (*CiProductRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *CiProduct) SetRelationships(v CiProductRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *CiProduct) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *CiProduct) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *CiProduct) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *CiProduct) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


