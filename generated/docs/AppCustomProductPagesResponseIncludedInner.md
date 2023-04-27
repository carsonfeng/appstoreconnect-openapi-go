# AppCustomProductPagesResponseIncludedInner

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**AppCustomProductPageVersionAttributes**](AppCustomProductPageVersionAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**AppCustomProductPageVersionRelationships**](AppCustomProductPageVersionRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewAppCustomProductPagesResponseIncludedInner

`func NewAppCustomProductPagesResponseIncludedInner(type_ string, id string, links ResourceLinks, ) *AppCustomProductPagesResponseIncludedInner`

NewAppCustomProductPagesResponseIncludedInner instantiates a new AppCustomProductPagesResponseIncludedInner object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppCustomProductPagesResponseIncludedInnerWithDefaults

`func NewAppCustomProductPagesResponseIncludedInnerWithDefaults() *AppCustomProductPagesResponseIncludedInner`

NewAppCustomProductPagesResponseIncludedInnerWithDefaults instantiates a new AppCustomProductPagesResponseIncludedInner object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *AppCustomProductPagesResponseIncludedInner) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *AppCustomProductPagesResponseIncludedInner) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *AppCustomProductPagesResponseIncludedInner) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *AppCustomProductPagesResponseIncludedInner) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *AppCustomProductPagesResponseIncludedInner) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *AppCustomProductPagesResponseIncludedInner) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *AppCustomProductPagesResponseIncludedInner) GetAttributes() AppCustomProductPageVersionAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *AppCustomProductPagesResponseIncludedInner) GetAttributesOk() (*AppCustomProductPageVersionAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *AppCustomProductPagesResponseIncludedInner) SetAttributes(v AppCustomProductPageVersionAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *AppCustomProductPagesResponseIncludedInner) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *AppCustomProductPagesResponseIncludedInner) GetRelationships() AppCustomProductPageVersionRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *AppCustomProductPagesResponseIncludedInner) GetRelationshipsOk() (*AppCustomProductPageVersionRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *AppCustomProductPagesResponseIncludedInner) SetRelationships(v AppCustomProductPageVersionRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *AppCustomProductPagesResponseIncludedInner) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *AppCustomProductPagesResponseIncludedInner) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppCustomProductPagesResponseIncludedInner) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppCustomProductPagesResponseIncludedInner) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


