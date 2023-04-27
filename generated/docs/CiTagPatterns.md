# CiTagPatterns

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**IsAllMatch** | Pointer to **bool** |  | [optional] 
**Patterns** | Pointer to [**[]CiBranchPatternsPatternsInner**](CiBranchPatternsPatternsInner.md) |  | [optional] 

## Methods

### NewCiTagPatterns

`func NewCiTagPatterns() *CiTagPatterns`

NewCiTagPatterns instantiates a new CiTagPatterns object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCiTagPatternsWithDefaults

`func NewCiTagPatternsWithDefaults() *CiTagPatterns`

NewCiTagPatternsWithDefaults instantiates a new CiTagPatterns object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetIsAllMatch

`func (o *CiTagPatterns) GetIsAllMatch() bool`

GetIsAllMatch returns the IsAllMatch field if non-nil, zero value otherwise.

### GetIsAllMatchOk

`func (o *CiTagPatterns) GetIsAllMatchOk() (*bool, bool)`

GetIsAllMatchOk returns a tuple with the IsAllMatch field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIsAllMatch

`func (o *CiTagPatterns) SetIsAllMatch(v bool)`

SetIsAllMatch sets IsAllMatch field to given value.

### HasIsAllMatch

`func (o *CiTagPatterns) HasIsAllMatch() bool`

HasIsAllMatch returns a boolean if a field has been set.

### GetPatterns

`func (o *CiTagPatterns) GetPatterns() []CiBranchPatternsPatternsInner`

GetPatterns returns the Patterns field if non-nil, zero value otherwise.

### GetPatternsOk

`func (o *CiTagPatterns) GetPatternsOk() (*[]CiBranchPatternsPatternsInner, bool)`

GetPatternsOk returns a tuple with the Patterns field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPatterns

`func (o *CiTagPatterns) SetPatterns(v []CiBranchPatternsPatternsInner)`

SetPatterns sets Patterns field to given value.

### HasPatterns

`func (o *CiTagPatterns) HasPatterns() bool`

HasPatterns returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


