# CiPullRequestStartCondition

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Source** | Pointer to [**CiBranchPatterns**](CiBranchPatterns.md) |  | [optional] 
**Destination** | Pointer to [**CiBranchPatterns**](CiBranchPatterns.md) |  | [optional] 
**FilesAndFoldersRule** | Pointer to [**CiFilesAndFoldersRule**](CiFilesAndFoldersRule.md) |  | [optional] 
**AutoCancel** | Pointer to **bool** |  | [optional] 

## Methods

### NewCiPullRequestStartCondition

`func NewCiPullRequestStartCondition() *CiPullRequestStartCondition`

NewCiPullRequestStartCondition instantiates a new CiPullRequestStartCondition object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCiPullRequestStartConditionWithDefaults

`func NewCiPullRequestStartConditionWithDefaults() *CiPullRequestStartCondition`

NewCiPullRequestStartConditionWithDefaults instantiates a new CiPullRequestStartCondition object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetSource

`func (o *CiPullRequestStartCondition) GetSource() CiBranchPatterns`

GetSource returns the Source field if non-nil, zero value otherwise.

### GetSourceOk

`func (o *CiPullRequestStartCondition) GetSourceOk() (*CiBranchPatterns, bool)`

GetSourceOk returns a tuple with the Source field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSource

`func (o *CiPullRequestStartCondition) SetSource(v CiBranchPatterns)`

SetSource sets Source field to given value.

### HasSource

`func (o *CiPullRequestStartCondition) HasSource() bool`

HasSource returns a boolean if a field has been set.

### GetDestination

`func (o *CiPullRequestStartCondition) GetDestination() CiBranchPatterns`

GetDestination returns the Destination field if non-nil, zero value otherwise.

### GetDestinationOk

`func (o *CiPullRequestStartCondition) GetDestinationOk() (*CiBranchPatterns, bool)`

GetDestinationOk returns a tuple with the Destination field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDestination

`func (o *CiPullRequestStartCondition) SetDestination(v CiBranchPatterns)`

SetDestination sets Destination field to given value.

### HasDestination

`func (o *CiPullRequestStartCondition) HasDestination() bool`

HasDestination returns a boolean if a field has been set.

### GetFilesAndFoldersRule

`func (o *CiPullRequestStartCondition) GetFilesAndFoldersRule() CiFilesAndFoldersRule`

GetFilesAndFoldersRule returns the FilesAndFoldersRule field if non-nil, zero value otherwise.

### GetFilesAndFoldersRuleOk

`func (o *CiPullRequestStartCondition) GetFilesAndFoldersRuleOk() (*CiFilesAndFoldersRule, bool)`

GetFilesAndFoldersRuleOk returns a tuple with the FilesAndFoldersRule field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFilesAndFoldersRule

`func (o *CiPullRequestStartCondition) SetFilesAndFoldersRule(v CiFilesAndFoldersRule)`

SetFilesAndFoldersRule sets FilesAndFoldersRule field to given value.

### HasFilesAndFoldersRule

`func (o *CiPullRequestStartCondition) HasFilesAndFoldersRule() bool`

HasFilesAndFoldersRule returns a boolean if a field has been set.

### GetAutoCancel

`func (o *CiPullRequestStartCondition) GetAutoCancel() bool`

GetAutoCancel returns the AutoCancel field if non-nil, zero value otherwise.

### GetAutoCancelOk

`func (o *CiPullRequestStartCondition) GetAutoCancelOk() (*bool, bool)`

GetAutoCancelOk returns a tuple with the AutoCancel field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAutoCancel

`func (o *CiPullRequestStartCondition) SetAutoCancel(v bool)`

SetAutoCancel sets AutoCancel field to given value.

### HasAutoCancel

`func (o *CiPullRequestStartCondition) HasAutoCancel() bool`

HasAutoCancel returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


