# AppCategoriesResponseIncludedInner

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**AppCategoryAttributes**](AppCategoryAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**AppCategoryRelationships**](AppCategoryRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewAppCategoriesResponseIncludedInner

`func NewAppCategoriesResponseIncludedInner(type_ string, id string, links ResourceLinks, ) *AppCategoriesResponseIncludedInner`

NewAppCategoriesResponseIncludedInner instantiates a new AppCategoriesResponseIncludedInner object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppCategoriesResponseIncludedInnerWithDefaults

`func NewAppCategoriesResponseIncludedInnerWithDefaults() *AppCategoriesResponseIncludedInner`

NewAppCategoriesResponseIncludedInnerWithDefaults instantiates a new AppCategoriesResponseIncludedInner object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *AppCategoriesResponseIncludedInner) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *AppCategoriesResponseIncludedInner) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *AppCategoriesResponseIncludedInner) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *AppCategoriesResponseIncludedInner) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *AppCategoriesResponseIncludedInner) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *AppCategoriesResponseIncludedInner) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *AppCategoriesResponseIncludedInner) GetAttributes() AppCategoryAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *AppCategoriesResponseIncludedInner) GetAttributesOk() (*AppCategoryAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *AppCategoriesResponseIncludedInner) SetAttributes(v AppCategoryAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *AppCategoriesResponseIncludedInner) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *AppCategoriesResponseIncludedInner) GetRelationships() AppCategoryRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *AppCategoriesResponseIncludedInner) GetRelationshipsOk() (*AppCategoryRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *AppCategoriesResponseIncludedInner) SetRelationships(v AppCategoryRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *AppCategoriesResponseIncludedInner) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *AppCategoriesResponseIncludedInner) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppCategoriesResponseIncludedInner) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppCategoriesResponseIncludedInner) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


