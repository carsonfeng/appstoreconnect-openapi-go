# CiBuildRunsResponseIncludedInner

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**ScmPullRequestAttributes**](ScmPullRequestAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**ScmGitReferenceRelationships**](ScmGitReferenceRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewCiBuildRunsResponseIncludedInner

`func NewCiBuildRunsResponseIncludedInner(type_ string, id string, links ResourceLinks, ) *CiBuildRunsResponseIncludedInner`

NewCiBuildRunsResponseIncludedInner instantiates a new CiBuildRunsResponseIncludedInner object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCiBuildRunsResponseIncludedInnerWithDefaults

`func NewCiBuildRunsResponseIncludedInnerWithDefaults() *CiBuildRunsResponseIncludedInner`

NewCiBuildRunsResponseIncludedInnerWithDefaults instantiates a new CiBuildRunsResponseIncludedInner object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *CiBuildRunsResponseIncludedInner) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *CiBuildRunsResponseIncludedInner) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *CiBuildRunsResponseIncludedInner) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *CiBuildRunsResponseIncludedInner) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *CiBuildRunsResponseIncludedInner) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *CiBuildRunsResponseIncludedInner) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *CiBuildRunsResponseIncludedInner) GetAttributes() ScmPullRequestAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *CiBuildRunsResponseIncludedInner) GetAttributesOk() (*ScmPullRequestAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *CiBuildRunsResponseIncludedInner) SetAttributes(v ScmPullRequestAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *CiBuildRunsResponseIncludedInner) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *CiBuildRunsResponseIncludedInner) GetRelationships() ScmGitReferenceRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *CiBuildRunsResponseIncludedInner) GetRelationshipsOk() (*ScmGitReferenceRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *CiBuildRunsResponseIncludedInner) SetRelationships(v ScmGitReferenceRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *CiBuildRunsResponseIncludedInner) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *CiBuildRunsResponseIncludedInner) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *CiBuildRunsResponseIncludedInner) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *CiBuildRunsResponseIncludedInner) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


