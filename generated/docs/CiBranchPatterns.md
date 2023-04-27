# CiBranchPatterns

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**IsAllMatch** | Pointer to **bool** |  | [optional] 
**Patterns** | Pointer to [**[]CiBranchPatternsPatternsInner**](CiBranchPatternsPatternsInner.md) |  | [optional] 

## Methods

### NewCiBranchPatterns

`func NewCiBranchPatterns() *CiBranchPatterns`

NewCiBranchPatterns instantiates a new CiBranchPatterns object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCiBranchPatternsWithDefaults

`func NewCiBranchPatternsWithDefaults() *CiBranchPatterns`

NewCiBranchPatternsWithDefaults instantiates a new CiBranchPatterns object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetIsAllMatch

`func (o *CiBranchPatterns) GetIsAllMatch() bool`

GetIsAllMatch returns the IsAllMatch field if non-nil, zero value otherwise.

### GetIsAllMatchOk

`func (o *CiBranchPatterns) GetIsAllMatchOk() (*bool, bool)`

GetIsAllMatchOk returns a tuple with the IsAllMatch field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIsAllMatch

`func (o *CiBranchPatterns) SetIsAllMatch(v bool)`

SetIsAllMatch sets IsAllMatch field to given value.

### HasIsAllMatch

`func (o *CiBranchPatterns) HasIsAllMatch() bool`

HasIsAllMatch returns a boolean if a field has been set.

### GetPatterns

`func (o *CiBranchPatterns) GetPatterns() []CiBranchPatternsPatternsInner`

GetPatterns returns the Patterns field if non-nil, zero value otherwise.

### GetPatternsOk

`func (o *CiBranchPatterns) GetPatternsOk() (*[]CiBranchPatternsPatternsInner, bool)`

GetPatternsOk returns a tuple with the Patterns field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPatterns

`func (o *CiBranchPatterns) SetPatterns(v []CiBranchPatternsPatternsInner)`

SetPatterns sets Patterns field to given value.

### HasPatterns

`func (o *CiBranchPatterns) HasPatterns() bool`

HasPatterns returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


