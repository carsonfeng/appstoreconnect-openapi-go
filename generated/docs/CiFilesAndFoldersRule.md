# CiFilesAndFoldersRule

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Mode** | Pointer to **string** |  | [optional] 
**Matchers** | Pointer to [**[]CiStartConditionFileMatcher**](CiStartConditionFileMatcher.md) |  | [optional] 

## Methods

### NewCiFilesAndFoldersRule

`func NewCiFilesAndFoldersRule() *CiFilesAndFoldersRule`

NewCiFilesAndFoldersRule instantiates a new CiFilesAndFoldersRule object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCiFilesAndFoldersRuleWithDefaults

`func NewCiFilesAndFoldersRuleWithDefaults() *CiFilesAndFoldersRule`

NewCiFilesAndFoldersRuleWithDefaults instantiates a new CiFilesAndFoldersRule object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetMode

`func (o *CiFilesAndFoldersRule) GetMode() string`

GetMode returns the Mode field if non-nil, zero value otherwise.

### GetModeOk

`func (o *CiFilesAndFoldersRule) GetModeOk() (*string, bool)`

GetModeOk returns a tuple with the Mode field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMode

`func (o *CiFilesAndFoldersRule) SetMode(v string)`

SetMode sets Mode field to given value.

### HasMode

`func (o *CiFilesAndFoldersRule) HasMode() bool`

HasMode returns a boolean if a field has been set.

### GetMatchers

`func (o *CiFilesAndFoldersRule) GetMatchers() []CiStartConditionFileMatcher`

GetMatchers returns the Matchers field if non-nil, zero value otherwise.

### GetMatchersOk

`func (o *CiFilesAndFoldersRule) GetMatchersOk() (*[]CiStartConditionFileMatcher, bool)`

GetMatchersOk returns a tuple with the Matchers field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMatchers

`func (o *CiFilesAndFoldersRule) SetMatchers(v []CiStartConditionFileMatcher)`

SetMatchers sets Matchers field to given value.

### HasMatchers

`func (o *CiFilesAndFoldersRule) HasMatchers() bool`

HasMatchers returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


