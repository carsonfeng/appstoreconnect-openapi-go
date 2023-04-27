# CiScheduledStartCondition

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Source** | Pointer to [**CiBranchPatterns**](CiBranchPatterns.md) |  | [optional] 
**Schedule** | Pointer to [**CiScheduledStartConditionSchedule**](CiScheduledStartConditionSchedule.md) |  | [optional] 

## Methods

### NewCiScheduledStartCondition

`func NewCiScheduledStartCondition() *CiScheduledStartCondition`

NewCiScheduledStartCondition instantiates a new CiScheduledStartCondition object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCiScheduledStartConditionWithDefaults

`func NewCiScheduledStartConditionWithDefaults() *CiScheduledStartCondition`

NewCiScheduledStartConditionWithDefaults instantiates a new CiScheduledStartCondition object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetSource

`func (o *CiScheduledStartCondition) GetSource() CiBranchPatterns`

GetSource returns the Source field if non-nil, zero value otherwise.

### GetSourceOk

`func (o *CiScheduledStartCondition) GetSourceOk() (*CiBranchPatterns, bool)`

GetSourceOk returns a tuple with the Source field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSource

`func (o *CiScheduledStartCondition) SetSource(v CiBranchPatterns)`

SetSource sets Source field to given value.

### HasSource

`func (o *CiScheduledStartCondition) HasSource() bool`

HasSource returns a boolean if a field has been set.

### GetSchedule

`func (o *CiScheduledStartCondition) GetSchedule() CiScheduledStartConditionSchedule`

GetSchedule returns the Schedule field if non-nil, zero value otherwise.

### GetScheduleOk

`func (o *CiScheduledStartCondition) GetScheduleOk() (*CiScheduledStartConditionSchedule, bool)`

GetScheduleOk returns a tuple with the Schedule field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSchedule

`func (o *CiScheduledStartCondition) SetSchedule(v CiScheduledStartConditionSchedule)`

SetSchedule sets Schedule field to given value.

### HasSchedule

`func (o *CiScheduledStartCondition) HasSchedule() bool`

HasSchedule returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


