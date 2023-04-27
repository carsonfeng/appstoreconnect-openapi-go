# CiProductsResponseIncludedInner

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**ScmRepositoryAttributes**](ScmRepositoryAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**ScmRepositoryRelationships**](ScmRepositoryRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewCiProductsResponseIncludedInner

`func NewCiProductsResponseIncludedInner(type_ string, id string, links ResourceLinks, ) *CiProductsResponseIncludedInner`

NewCiProductsResponseIncludedInner instantiates a new CiProductsResponseIncludedInner object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCiProductsResponseIncludedInnerWithDefaults

`func NewCiProductsResponseIncludedInnerWithDefaults() *CiProductsResponseIncludedInner`

NewCiProductsResponseIncludedInnerWithDefaults instantiates a new CiProductsResponseIncludedInner object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *CiProductsResponseIncludedInner) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *CiProductsResponseIncludedInner) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *CiProductsResponseIncludedInner) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *CiProductsResponseIncludedInner) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *CiProductsResponseIncludedInner) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *CiProductsResponseIncludedInner) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *CiProductsResponseIncludedInner) GetAttributes() ScmRepositoryAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *CiProductsResponseIncludedInner) GetAttributesOk() (*ScmRepositoryAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *CiProductsResponseIncludedInner) SetAttributes(v ScmRepositoryAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *CiProductsResponseIncludedInner) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *CiProductsResponseIncludedInner) GetRelationships() ScmRepositoryRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *CiProductsResponseIncludedInner) GetRelationshipsOk() (*ScmRepositoryRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *CiProductsResponseIncludedInner) SetRelationships(v ScmRepositoryRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *CiProductsResponseIncludedInner) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *CiProductsResponseIncludedInner) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *CiProductsResponseIncludedInner) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *CiProductsResponseIncludedInner) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


