# AppInfosResponseIncludedInner

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**AppCategoryAttributes**](AppCategoryAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**AppCategoryRelationships**](AppCategoryRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewAppInfosResponseIncludedInner

`func NewAppInfosResponseIncludedInner(type_ string, id string, links ResourceLinks, ) *AppInfosResponseIncludedInner`

NewAppInfosResponseIncludedInner instantiates a new AppInfosResponseIncludedInner object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppInfosResponseIncludedInnerWithDefaults

`func NewAppInfosResponseIncludedInnerWithDefaults() *AppInfosResponseIncludedInner`

NewAppInfosResponseIncludedInnerWithDefaults instantiates a new AppInfosResponseIncludedInner object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *AppInfosResponseIncludedInner) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *AppInfosResponseIncludedInner) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *AppInfosResponseIncludedInner) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *AppInfosResponseIncludedInner) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *AppInfosResponseIncludedInner) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *AppInfosResponseIncludedInner) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *AppInfosResponseIncludedInner) GetAttributes() AppCategoryAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *AppInfosResponseIncludedInner) GetAttributesOk() (*AppCategoryAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *AppInfosResponseIncludedInner) SetAttributes(v AppCategoryAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *AppInfosResponseIncludedInner) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *AppInfosResponseIncludedInner) GetRelationships() AppCategoryRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *AppInfosResponseIncludedInner) GetRelationshipsOk() (*AppCategoryRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *AppInfosResponseIncludedInner) SetRelationships(v AppCategoryRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *AppInfosResponseIncludedInner) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *AppInfosResponseIncludedInner) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppInfosResponseIncludedInner) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppInfosResponseIncludedInner) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


