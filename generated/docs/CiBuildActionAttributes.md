# CiBuildActionAttributes

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Name** | Pointer to **string** |  | [optional] 
**ActionType** | Pointer to [**CiActionType**](CiActionType.md) |  | [optional] 
**StartedDate** | Pointer to **time.Time** |  | [optional] 
**FinishedDate** | Pointer to **time.Time** |  | [optional] 
**IssueCounts** | Pointer to [**CiIssueCounts**](CiIssueCounts.md) |  | [optional] 
**ExecutionProgress** | Pointer to [**CiExecutionProgress**](CiExecutionProgress.md) |  | [optional] 
**CompletionStatus** | Pointer to [**CiCompletionStatus**](CiCompletionStatus.md) |  | [optional] 
**IsRequiredToPass** | Pointer to **bool** |  | [optional] 

## Methods

### NewCiBuildActionAttributes

`func NewCiBuildActionAttributes() *CiBuildActionAttributes`

NewCiBuildActionAttributes instantiates a new CiBuildActionAttributes object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCiBuildActionAttributesWithDefaults

`func NewCiBuildActionAttributesWithDefaults() *CiBuildActionAttributes`

NewCiBuildActionAttributesWithDefaults instantiates a new CiBuildActionAttributes object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetName

`func (o *CiBuildActionAttributes) GetName() string`

GetName returns the Name field if non-nil, zero value otherwise.

### GetNameOk

`func (o *CiBuildActionAttributes) GetNameOk() (*string, bool)`

GetNameOk returns a tuple with the Name field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetName

`func (o *CiBuildActionAttributes) SetName(v string)`

SetName sets Name field to given value.

### HasName

`func (o *CiBuildActionAttributes) HasName() bool`

HasName returns a boolean if a field has been set.

### GetActionType

`func (o *CiBuildActionAttributes) GetActionType() CiActionType`

GetActionType returns the ActionType field if non-nil, zero value otherwise.

### GetActionTypeOk

`func (o *CiBuildActionAttributes) GetActionTypeOk() (*CiActionType, bool)`

GetActionTypeOk returns a tuple with the ActionType field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetActionType

`func (o *CiBuildActionAttributes) SetActionType(v CiActionType)`

SetActionType sets ActionType field to given value.

### HasActionType

`func (o *CiBuildActionAttributes) HasActionType() bool`

HasActionType returns a boolean if a field has been set.

### GetStartedDate

`func (o *CiBuildActionAttributes) GetStartedDate() time.Time`

GetStartedDate returns the StartedDate field if non-nil, zero value otherwise.

### GetStartedDateOk

`func (o *CiBuildActionAttributes) GetStartedDateOk() (*time.Time, bool)`

GetStartedDateOk returns a tuple with the StartedDate field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetStartedDate

`func (o *CiBuildActionAttributes) SetStartedDate(v time.Time)`

SetStartedDate sets StartedDate field to given value.

### HasStartedDate

`func (o *CiBuildActionAttributes) HasStartedDate() bool`

HasStartedDate returns a boolean if a field has been set.

### GetFinishedDate

`func (o *CiBuildActionAttributes) GetFinishedDate() time.Time`

GetFinishedDate returns the FinishedDate field if non-nil, zero value otherwise.

### GetFinishedDateOk

`func (o *CiBuildActionAttributes) GetFinishedDateOk() (*time.Time, bool)`

GetFinishedDateOk returns a tuple with the FinishedDate field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFinishedDate

`func (o *CiBuildActionAttributes) SetFinishedDate(v time.Time)`

SetFinishedDate sets FinishedDate field to given value.

### HasFinishedDate

`func (o *CiBuildActionAttributes) HasFinishedDate() bool`

HasFinishedDate returns a boolean if a field has been set.

### GetIssueCounts

`func (o *CiBuildActionAttributes) GetIssueCounts() CiIssueCounts`

GetIssueCounts returns the IssueCounts field if non-nil, zero value otherwise.

### GetIssueCountsOk

`func (o *CiBuildActionAttributes) GetIssueCountsOk() (*CiIssueCounts, bool)`

GetIssueCountsOk returns a tuple with the IssueCounts field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIssueCounts

`func (o *CiBuildActionAttributes) SetIssueCounts(v CiIssueCounts)`

SetIssueCounts sets IssueCounts field to given value.

### HasIssueCounts

`func (o *CiBuildActionAttributes) HasIssueCounts() bool`

HasIssueCounts returns a boolean if a field has been set.

### GetExecutionProgress

`func (o *CiBuildActionAttributes) GetExecutionProgress() CiExecutionProgress`

GetExecutionProgress returns the ExecutionProgress field if non-nil, zero value otherwise.

### GetExecutionProgressOk

`func (o *CiBuildActionAttributes) GetExecutionProgressOk() (*CiExecutionProgress, bool)`

GetExecutionProgressOk returns a tuple with the ExecutionProgress field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetExecutionProgress

`func (o *CiBuildActionAttributes) SetExecutionProgress(v CiExecutionProgress)`

SetExecutionProgress sets ExecutionProgress field to given value.

### HasExecutionProgress

`func (o *CiBuildActionAttributes) HasExecutionProgress() bool`

HasExecutionProgress returns a boolean if a field has been set.

### GetCompletionStatus

`func (o *CiBuildActionAttributes) GetCompletionStatus() CiCompletionStatus`

GetCompletionStatus returns the CompletionStatus field if non-nil, zero value otherwise.

### GetCompletionStatusOk

`func (o *CiBuildActionAttributes) GetCompletionStatusOk() (*CiCompletionStatus, bool)`

GetCompletionStatusOk returns a tuple with the CompletionStatus field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCompletionStatus

`func (o *CiBuildActionAttributes) SetCompletionStatus(v CiCompletionStatus)`

SetCompletionStatus sets CompletionStatus field to given value.

### HasCompletionStatus

`func (o *CiBuildActionAttributes) HasCompletionStatus() bool`

HasCompletionStatus returns a boolean if a field has been set.

### GetIsRequiredToPass

`func (o *CiBuildActionAttributes) GetIsRequiredToPass() bool`

GetIsRequiredToPass returns the IsRequiredToPass field if non-nil, zero value otherwise.

### GetIsRequiredToPassOk

`func (o *CiBuildActionAttributes) GetIsRequiredToPassOk() (*bool, bool)`

GetIsRequiredToPassOk returns a tuple with the IsRequiredToPass field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIsRequiredToPass

`func (o *CiBuildActionAttributes) SetIsRequiredToPass(v bool)`

SetIsRequiredToPass sets IsRequiredToPass field to given value.

### HasIsRequiredToPass

`func (o *CiBuildActionAttributes) HasIsRequiredToPass() bool`

HasIsRequiredToPass returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


