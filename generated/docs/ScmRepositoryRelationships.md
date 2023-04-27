# ScmRepositoryRelationships

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**ScmProvider** | Pointer to [**ScmRepositoryRelationshipsScmProvider**](ScmRepositoryRelationshipsScmProvider.md) |  | [optional] 
**DefaultBranch** | Pointer to [**CiBuildRunRelationshipsSourceBranchOrTag**](CiBuildRunRelationshipsSourceBranchOrTag.md) |  | [optional] 

## Methods

### NewScmRepositoryRelationships

`func NewScmRepositoryRelationships() *ScmRepositoryRelationships`

NewScmRepositoryRelationships instantiates a new ScmRepositoryRelationships object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewScmRepositoryRelationshipsWithDefaults

`func NewScmRepositoryRelationshipsWithDefaults() *ScmRepositoryRelationships`

NewScmRepositoryRelationshipsWithDefaults instantiates a new ScmRepositoryRelationships object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetScmProvider

`func (o *ScmRepositoryRelationships) GetScmProvider() ScmRepositoryRelationshipsScmProvider`

GetScmProvider returns the ScmProvider field if non-nil, zero value otherwise.

### GetScmProviderOk

`func (o *ScmRepositoryRelationships) GetScmProviderOk() (*ScmRepositoryRelationshipsScmProvider, bool)`

GetScmProviderOk returns a tuple with the ScmProvider field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetScmProvider

`func (o *ScmRepositoryRelationships) SetScmProvider(v ScmRepositoryRelationshipsScmProvider)`

SetScmProvider sets ScmProvider field to given value.

### HasScmProvider

`func (o *ScmRepositoryRelationships) HasScmProvider() bool`

HasScmProvider returns a boolean if a field has been set.

### GetDefaultBranch

`func (o *ScmRepositoryRelationships) GetDefaultBranch() CiBuildRunRelationshipsSourceBranchOrTag`

GetDefaultBranch returns the DefaultBranch field if non-nil, zero value otherwise.

### GetDefaultBranchOk

`func (o *ScmRepositoryRelationships) GetDefaultBranchOk() (*CiBuildRunRelationshipsSourceBranchOrTag, bool)`

GetDefaultBranchOk returns a tuple with the DefaultBranch field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDefaultBranch

`func (o *ScmRepositoryRelationships) SetDefaultBranch(v CiBuildRunRelationshipsSourceBranchOrTag)`

SetDefaultBranch sets DefaultBranch field to given value.

### HasDefaultBranch

`func (o *ScmRepositoryRelationships) HasDefaultBranch() bool`

HasDefaultBranch returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


