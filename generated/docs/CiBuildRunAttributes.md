# CiBuildRunAttributes

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Number** | Pointer to **int32** |  | [optional] 
**CreatedDate** | Pointer to **time.Time** |  | [optional] 
**StartedDate** | Pointer to **time.Time** |  | [optional] 
**FinishedDate** | Pointer to **time.Time** |  | [optional] 
**SourceCommit** | Pointer to [**CiBuildRunAttributesSourceCommit**](CiBuildRunAttributesSourceCommit.md) |  | [optional] 
**DestinationCommit** | Pointer to [**CiBuildRunAttributesSourceCommit**](CiBuildRunAttributesSourceCommit.md) |  | [optional] 
**IsPullRequestBuild** | Pointer to **bool** |  | [optional] 
**IssueCounts** | Pointer to [**CiIssueCounts**](CiIssueCounts.md) |  | [optional] 
**ExecutionProgress** | Pointer to [**CiExecutionProgress**](CiExecutionProgress.md) |  | [optional] 
**CompletionStatus** | Pointer to [**CiCompletionStatus**](CiCompletionStatus.md) |  | [optional] 
**StartReason** | Pointer to **string** |  | [optional] 
**CancelReason** | Pointer to **string** |  | [optional] 

## Methods

### NewCiBuildRunAttributes

`func NewCiBuildRunAttributes() *CiBuildRunAttributes`

NewCiBuildRunAttributes instantiates a new CiBuildRunAttributes object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCiBuildRunAttributesWithDefaults

`func NewCiBuildRunAttributesWithDefaults() *CiBuildRunAttributes`

NewCiBuildRunAttributesWithDefaults instantiates a new CiBuildRunAttributes object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetNumber

`func (o *CiBuildRunAttributes) GetNumber() int32`

GetNumber returns the Number field if non-nil, zero value otherwise.

### GetNumberOk

`func (o *CiBuildRunAttributes) GetNumberOk() (*int32, bool)`

GetNumberOk returns a tuple with the Number field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetNumber

`func (o *CiBuildRunAttributes) SetNumber(v int32)`

SetNumber sets Number field to given value.

### HasNumber

`func (o *CiBuildRunAttributes) HasNumber() bool`

HasNumber returns a boolean if a field has been set.

### GetCreatedDate

`func (o *CiBuildRunAttributes) GetCreatedDate() time.Time`

GetCreatedDate returns the CreatedDate field if non-nil, zero value otherwise.

### GetCreatedDateOk

`func (o *CiBuildRunAttributes) GetCreatedDateOk() (*time.Time, bool)`

GetCreatedDateOk returns a tuple with the CreatedDate field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCreatedDate

`func (o *CiBuildRunAttributes) SetCreatedDate(v time.Time)`

SetCreatedDate sets CreatedDate field to given value.

### HasCreatedDate

`func (o *CiBuildRunAttributes) HasCreatedDate() bool`

HasCreatedDate returns a boolean if a field has been set.

### GetStartedDate

`func (o *CiBuildRunAttributes) GetStartedDate() time.Time`

GetStartedDate returns the StartedDate field if non-nil, zero value otherwise.

### GetStartedDateOk

`func (o *CiBuildRunAttributes) GetStartedDateOk() (*time.Time, bool)`

GetStartedDateOk returns a tuple with the StartedDate field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetStartedDate

`func (o *CiBuildRunAttributes) SetStartedDate(v time.Time)`

SetStartedDate sets StartedDate field to given value.

### HasStartedDate

`func (o *CiBuildRunAttributes) HasStartedDate() bool`

HasStartedDate returns a boolean if a field has been set.

### GetFinishedDate

`func (o *CiBuildRunAttributes) GetFinishedDate() time.Time`

GetFinishedDate returns the FinishedDate field if non-nil, zero value otherwise.

### GetFinishedDateOk

`func (o *CiBuildRunAttributes) GetFinishedDateOk() (*time.Time, bool)`

GetFinishedDateOk returns a tuple with the FinishedDate field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFinishedDate

`func (o *CiBuildRunAttributes) SetFinishedDate(v time.Time)`

SetFinishedDate sets FinishedDate field to given value.

### HasFinishedDate

`func (o *CiBuildRunAttributes) HasFinishedDate() bool`

HasFinishedDate returns a boolean if a field has been set.

### GetSourceCommit

`func (o *CiBuildRunAttributes) GetSourceCommit() CiBuildRunAttributesSourceCommit`

GetSourceCommit returns the SourceCommit field if non-nil, zero value otherwise.

### GetSourceCommitOk

`func (o *CiBuildRunAttributes) GetSourceCommitOk() (*CiBuildRunAttributesSourceCommit, bool)`

GetSourceCommitOk returns a tuple with the SourceCommit field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSourceCommit

`func (o *CiBuildRunAttributes) SetSourceCommit(v CiBuildRunAttributesSourceCommit)`

SetSourceCommit sets SourceCommit field to given value.

### HasSourceCommit

`func (o *CiBuildRunAttributes) HasSourceCommit() bool`

HasSourceCommit returns a boolean if a field has been set.

### GetDestinationCommit

`func (o *CiBuildRunAttributes) GetDestinationCommit() CiBuildRunAttributesSourceCommit`

GetDestinationCommit returns the DestinationCommit field if non-nil, zero value otherwise.

### GetDestinationCommitOk

`func (o *CiBuildRunAttributes) GetDestinationCommitOk() (*CiBuildRunAttributesSourceCommit, bool)`

GetDestinationCommitOk returns a tuple with the DestinationCommit field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDestinationCommit

`func (o *CiBuildRunAttributes) SetDestinationCommit(v CiBuildRunAttributesSourceCommit)`

SetDestinationCommit sets DestinationCommit field to given value.

### HasDestinationCommit

`func (o *CiBuildRunAttributes) HasDestinationCommit() bool`

HasDestinationCommit returns a boolean if a field has been set.

### GetIsPullRequestBuild

`func (o *CiBuildRunAttributes) GetIsPullRequestBuild() bool`

GetIsPullRequestBuild returns the IsPullRequestBuild field if non-nil, zero value otherwise.

### GetIsPullRequestBuildOk

`func (o *CiBuildRunAttributes) GetIsPullRequestBuildOk() (*bool, bool)`

GetIsPullRequestBuildOk returns a tuple with the IsPullRequestBuild field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIsPullRequestBuild

`func (o *CiBuildRunAttributes) SetIsPullRequestBuild(v bool)`

SetIsPullRequestBuild sets IsPullRequestBuild field to given value.

### HasIsPullRequestBuild

`func (o *CiBuildRunAttributes) HasIsPullRequestBuild() bool`

HasIsPullRequestBuild returns a boolean if a field has been set.

### GetIssueCounts

`func (o *CiBuildRunAttributes) GetIssueCounts() CiIssueCounts`

GetIssueCounts returns the IssueCounts field if non-nil, zero value otherwise.

### GetIssueCountsOk

`func (o *CiBuildRunAttributes) GetIssueCountsOk() (*CiIssueCounts, bool)`

GetIssueCountsOk returns a tuple with the IssueCounts field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIssueCounts

`func (o *CiBuildRunAttributes) SetIssueCounts(v CiIssueCounts)`

SetIssueCounts sets IssueCounts field to given value.

### HasIssueCounts

`func (o *CiBuildRunAttributes) HasIssueCounts() bool`

HasIssueCounts returns a boolean if a field has been set.

### GetExecutionProgress

`func (o *CiBuildRunAttributes) GetExecutionProgress() CiExecutionProgress`

GetExecutionProgress returns the ExecutionProgress field if non-nil, zero value otherwise.

### GetExecutionProgressOk

`func (o *CiBuildRunAttributes) GetExecutionProgressOk() (*CiExecutionProgress, bool)`

GetExecutionProgressOk returns a tuple with the ExecutionProgress field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetExecutionProgress

`func (o *CiBuildRunAttributes) SetExecutionProgress(v CiExecutionProgress)`

SetExecutionProgress sets ExecutionProgress field to given value.

### HasExecutionProgress

`func (o *CiBuildRunAttributes) HasExecutionProgress() bool`

HasExecutionProgress returns a boolean if a field has been set.

### GetCompletionStatus

`func (o *CiBuildRunAttributes) GetCompletionStatus() CiCompletionStatus`

GetCompletionStatus returns the CompletionStatus field if non-nil, zero value otherwise.

### GetCompletionStatusOk

`func (o *CiBuildRunAttributes) GetCompletionStatusOk() (*CiCompletionStatus, bool)`

GetCompletionStatusOk returns a tuple with the CompletionStatus field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCompletionStatus

`func (o *CiBuildRunAttributes) SetCompletionStatus(v CiCompletionStatus)`

SetCompletionStatus sets CompletionStatus field to given value.

### HasCompletionStatus

`func (o *CiBuildRunAttributes) HasCompletionStatus() bool`

HasCompletionStatus returns a boolean if a field has been set.

### GetStartReason

`func (o *CiBuildRunAttributes) GetStartReason() string`

GetStartReason returns the StartReason field if non-nil, zero value otherwise.

### GetStartReasonOk

`func (o *CiBuildRunAttributes) GetStartReasonOk() (*string, bool)`

GetStartReasonOk returns a tuple with the StartReason field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetStartReason

`func (o *CiBuildRunAttributes) SetStartReason(v string)`

SetStartReason sets StartReason field to given value.

### HasStartReason

`func (o *CiBuildRunAttributes) HasStartReason() bool`

HasStartReason returns a boolean if a field has been set.

### GetCancelReason

`func (o *CiBuildRunAttributes) GetCancelReason() string`

GetCancelReason returns the CancelReason field if non-nil, zero value otherwise.

### GetCancelReasonOk

`func (o *CiBuildRunAttributes) GetCancelReasonOk() (*string, bool)`

GetCancelReasonOk returns a tuple with the CancelReason field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCancelReason

`func (o *CiBuildRunAttributes) SetCancelReason(v string)`

SetCancelReason sets CancelReason field to given value.

### HasCancelReason

`func (o *CiBuildRunAttributes) HasCancelReason() bool`

HasCancelReason returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


