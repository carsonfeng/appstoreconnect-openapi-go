# ScmGitReference

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**ScmGitReferenceAttributes**](ScmGitReferenceAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**ScmGitReferenceRelationships**](ScmGitReferenceRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewScmGitReference

`func NewScmGitReference(type_ string, id string, links ResourceLinks, ) *ScmGitReference`

NewScmGitReference instantiates a new ScmGitReference object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewScmGitReferenceWithDefaults

`func NewScmGitReferenceWithDefaults() *ScmGitReference`

NewScmGitReferenceWithDefaults instantiates a new ScmGitReference object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *ScmGitReference) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *ScmGitReference) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *ScmGitReference) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *ScmGitReference) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *ScmGitReference) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *ScmGitReference) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *ScmGitReference) GetAttributes() ScmGitReferenceAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *ScmGitReference) GetAttributesOk() (*ScmGitReferenceAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *ScmGitReference) SetAttributes(v ScmGitReferenceAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *ScmGitReference) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *ScmGitReference) GetRelationships() ScmGitReferenceRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *ScmGitReference) GetRelationshipsOk() (*ScmGitReferenceRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *ScmGitReference) SetRelationships(v ScmGitReferenceRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *ScmGitReference) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *ScmGitReference) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *ScmGitReference) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *ScmGitReference) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


