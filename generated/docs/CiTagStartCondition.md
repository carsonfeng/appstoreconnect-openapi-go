# CiTagStartCondition

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Source** | Pointer to [**CiTagPatterns**](CiTagPatterns.md) |  | [optional] 
**FilesAndFoldersRule** | Pointer to [**CiFilesAndFoldersRule**](CiFilesAndFoldersRule.md) |  | [optional] 
**AutoCancel** | Pointer to **bool** |  | [optional] 

## Methods

### NewCiTagStartCondition

`func NewCiTagStartCondition() *CiTagStartCondition`

NewCiTagStartCondition instantiates a new CiTagStartCondition object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCiTagStartConditionWithDefaults

`func NewCiTagStartConditionWithDefaults() *CiTagStartCondition`

NewCiTagStartConditionWithDefaults instantiates a new CiTagStartCondition object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetSource

`func (o *CiTagStartCondition) GetSource() CiTagPatterns`

GetSource returns the Source field if non-nil, zero value otherwise.

### GetSourceOk

`func (o *CiTagStartCondition) GetSourceOk() (*CiTagPatterns, bool)`

GetSourceOk returns a tuple with the Source field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSource

`func (o *CiTagStartCondition) SetSource(v CiTagPatterns)`

SetSource sets Source field to given value.

### HasSource

`func (o *CiTagStartCondition) HasSource() bool`

HasSource returns a boolean if a field has been set.

### GetFilesAndFoldersRule

`func (o *CiTagStartCondition) GetFilesAndFoldersRule() CiFilesAndFoldersRule`

GetFilesAndFoldersRule returns the FilesAndFoldersRule field if non-nil, zero value otherwise.

### GetFilesAndFoldersRuleOk

`func (o *CiTagStartCondition) GetFilesAndFoldersRuleOk() (*CiFilesAndFoldersRule, bool)`

GetFilesAndFoldersRuleOk returns a tuple with the FilesAndFoldersRule field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFilesAndFoldersRule

`func (o *CiTagStartCondition) SetFilesAndFoldersRule(v CiFilesAndFoldersRule)`

SetFilesAndFoldersRule sets FilesAndFoldersRule field to given value.

### HasFilesAndFoldersRule

`func (o *CiTagStartCondition) HasFilesAndFoldersRule() bool`

HasFilesAndFoldersRule returns a boolean if a field has been set.

### GetAutoCancel

`func (o *CiTagStartCondition) GetAutoCancel() bool`

GetAutoCancel returns the AutoCancel field if non-nil, zero value otherwise.

### GetAutoCancelOk

`func (o *CiTagStartCondition) GetAutoCancelOk() (*bool, bool)`

GetAutoCancelOk returns a tuple with the AutoCancel field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAutoCancel

`func (o *CiTagStartCondition) SetAutoCancel(v bool)`

SetAutoCancel sets AutoCancel field to given value.

### HasAutoCancel

`func (o *CiTagStartCondition) HasAutoCancel() bool`

HasAutoCancel returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


