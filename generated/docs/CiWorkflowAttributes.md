# CiWorkflowAttributes

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Name** | Pointer to **string** |  | [optional] 
**Description** | Pointer to **string** |  | [optional] 
**BranchStartCondition** | Pointer to [**CiBranchStartCondition**](CiBranchStartCondition.md) |  | [optional] 
**TagStartCondition** | Pointer to [**CiTagStartCondition**](CiTagStartCondition.md) |  | [optional] 
**PullRequestStartCondition** | Pointer to [**CiPullRequestStartCondition**](CiPullRequestStartCondition.md) |  | [optional] 
**ScheduledStartCondition** | Pointer to [**CiScheduledStartCondition**](CiScheduledStartCondition.md) |  | [optional] 
**Actions** | Pointer to [**[]CiAction**](CiAction.md) |  | [optional] 
**IsEnabled** | Pointer to **bool** |  | [optional] 
**IsLockedForEditing** | Pointer to **bool** |  | [optional] 
**Clean** | Pointer to **bool** |  | [optional] 
**ContainerFilePath** | Pointer to **string** |  | [optional] 
**LastModifiedDate** | Pointer to **time.Time** |  | [optional] 

## Methods

### NewCiWorkflowAttributes

`func NewCiWorkflowAttributes() *CiWorkflowAttributes`

NewCiWorkflowAttributes instantiates a new CiWorkflowAttributes object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCiWorkflowAttributesWithDefaults

`func NewCiWorkflowAttributesWithDefaults() *CiWorkflowAttributes`

NewCiWorkflowAttributesWithDefaults instantiates a new CiWorkflowAttributes object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetName

`func (o *CiWorkflowAttributes) GetName() string`

GetName returns the Name field if non-nil, zero value otherwise.

### GetNameOk

`func (o *CiWorkflowAttributes) GetNameOk() (*string, bool)`

GetNameOk returns a tuple with the Name field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetName

`func (o *CiWorkflowAttributes) SetName(v string)`

SetName sets Name field to given value.

### HasName

`func (o *CiWorkflowAttributes) HasName() bool`

HasName returns a boolean if a field has been set.

### GetDescription

`func (o *CiWorkflowAttributes) GetDescription() string`

GetDescription returns the Description field if non-nil, zero value otherwise.

### GetDescriptionOk

`func (o *CiWorkflowAttributes) GetDescriptionOk() (*string, bool)`

GetDescriptionOk returns a tuple with the Description field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDescription

`func (o *CiWorkflowAttributes) SetDescription(v string)`

SetDescription sets Description field to given value.

### HasDescription

`func (o *CiWorkflowAttributes) HasDescription() bool`

HasDescription returns a boolean if a field has been set.

### GetBranchStartCondition

`func (o *CiWorkflowAttributes) GetBranchStartCondition() CiBranchStartCondition`

GetBranchStartCondition returns the BranchStartCondition field if non-nil, zero value otherwise.

### GetBranchStartConditionOk

`func (o *CiWorkflowAttributes) GetBranchStartConditionOk() (*CiBranchStartCondition, bool)`

GetBranchStartConditionOk returns a tuple with the BranchStartCondition field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetBranchStartCondition

`func (o *CiWorkflowAttributes) SetBranchStartCondition(v CiBranchStartCondition)`

SetBranchStartCondition sets BranchStartCondition field to given value.

### HasBranchStartCondition

`func (o *CiWorkflowAttributes) HasBranchStartCondition() bool`

HasBranchStartCondition returns a boolean if a field has been set.

### GetTagStartCondition

`func (o *CiWorkflowAttributes) GetTagStartCondition() CiTagStartCondition`

GetTagStartCondition returns the TagStartCondition field if non-nil, zero value otherwise.

### GetTagStartConditionOk

`func (o *CiWorkflowAttributes) GetTagStartConditionOk() (*CiTagStartCondition, bool)`

GetTagStartConditionOk returns a tuple with the TagStartCondition field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTagStartCondition

`func (o *CiWorkflowAttributes) SetTagStartCondition(v CiTagStartCondition)`

SetTagStartCondition sets TagStartCondition field to given value.

### HasTagStartCondition

`func (o *CiWorkflowAttributes) HasTagStartCondition() bool`

HasTagStartCondition returns a boolean if a field has been set.

### GetPullRequestStartCondition

`func (o *CiWorkflowAttributes) GetPullRequestStartCondition() CiPullRequestStartCondition`

GetPullRequestStartCondition returns the PullRequestStartCondition field if non-nil, zero value otherwise.

### GetPullRequestStartConditionOk

`func (o *CiWorkflowAttributes) GetPullRequestStartConditionOk() (*CiPullRequestStartCondition, bool)`

GetPullRequestStartConditionOk returns a tuple with the PullRequestStartCondition field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPullRequestStartCondition

`func (o *CiWorkflowAttributes) SetPullRequestStartCondition(v CiPullRequestStartCondition)`

SetPullRequestStartCondition sets PullRequestStartCondition field to given value.

### HasPullRequestStartCondition

`func (o *CiWorkflowAttributes) HasPullRequestStartCondition() bool`

HasPullRequestStartCondition returns a boolean if a field has been set.

### GetScheduledStartCondition

`func (o *CiWorkflowAttributes) GetScheduledStartCondition() CiScheduledStartCondition`

GetScheduledStartCondition returns the ScheduledStartCondition field if non-nil, zero value otherwise.

### GetScheduledStartConditionOk

`func (o *CiWorkflowAttributes) GetScheduledStartConditionOk() (*CiScheduledStartCondition, bool)`

GetScheduledStartConditionOk returns a tuple with the ScheduledStartCondition field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetScheduledStartCondition

`func (o *CiWorkflowAttributes) SetScheduledStartCondition(v CiScheduledStartCondition)`

SetScheduledStartCondition sets ScheduledStartCondition field to given value.

### HasScheduledStartCondition

`func (o *CiWorkflowAttributes) HasScheduledStartCondition() bool`

HasScheduledStartCondition returns a boolean if a field has been set.

### GetActions

`func (o *CiWorkflowAttributes) GetActions() []CiAction`

GetActions returns the Actions field if non-nil, zero value otherwise.

### GetActionsOk

`func (o *CiWorkflowAttributes) GetActionsOk() (*[]CiAction, bool)`

GetActionsOk returns a tuple with the Actions field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetActions

`func (o *CiWorkflowAttributes) SetActions(v []CiAction)`

SetActions sets Actions field to given value.

### HasActions

`func (o *CiWorkflowAttributes) HasActions() bool`

HasActions returns a boolean if a field has been set.

### GetIsEnabled

`func (o *CiWorkflowAttributes) GetIsEnabled() bool`

GetIsEnabled returns the IsEnabled field if non-nil, zero value otherwise.

### GetIsEnabledOk

`func (o *CiWorkflowAttributes) GetIsEnabledOk() (*bool, bool)`

GetIsEnabledOk returns a tuple with the IsEnabled field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIsEnabled

`func (o *CiWorkflowAttributes) SetIsEnabled(v bool)`

SetIsEnabled sets IsEnabled field to given value.

### HasIsEnabled

`func (o *CiWorkflowAttributes) HasIsEnabled() bool`

HasIsEnabled returns a boolean if a field has been set.

### GetIsLockedForEditing

`func (o *CiWorkflowAttributes) GetIsLockedForEditing() bool`

GetIsLockedForEditing returns the IsLockedForEditing field if non-nil, zero value otherwise.

### GetIsLockedForEditingOk

`func (o *CiWorkflowAttributes) GetIsLockedForEditingOk() (*bool, bool)`

GetIsLockedForEditingOk returns a tuple with the IsLockedForEditing field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIsLockedForEditing

`func (o *CiWorkflowAttributes) SetIsLockedForEditing(v bool)`

SetIsLockedForEditing sets IsLockedForEditing field to given value.

### HasIsLockedForEditing

`func (o *CiWorkflowAttributes) HasIsLockedForEditing() bool`

HasIsLockedForEditing returns a boolean if a field has been set.

### GetClean

`func (o *CiWorkflowAttributes) GetClean() bool`

GetClean returns the Clean field if non-nil, zero value otherwise.

### GetCleanOk

`func (o *CiWorkflowAttributes) GetCleanOk() (*bool, bool)`

GetCleanOk returns a tuple with the Clean field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetClean

`func (o *CiWorkflowAttributes) SetClean(v bool)`

SetClean sets Clean field to given value.

### HasClean

`func (o *CiWorkflowAttributes) HasClean() bool`

HasClean returns a boolean if a field has been set.

### GetContainerFilePath

`func (o *CiWorkflowAttributes) GetContainerFilePath() string`

GetContainerFilePath returns the ContainerFilePath field if non-nil, zero value otherwise.

### GetContainerFilePathOk

`func (o *CiWorkflowAttributes) GetContainerFilePathOk() (*string, bool)`

GetContainerFilePathOk returns a tuple with the ContainerFilePath field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetContainerFilePath

`func (o *CiWorkflowAttributes) SetContainerFilePath(v string)`

SetContainerFilePath sets ContainerFilePath field to given value.

### HasContainerFilePath

`func (o *CiWorkflowAttributes) HasContainerFilePath() bool`

HasContainerFilePath returns a boolean if a field has been set.

### GetLastModifiedDate

`func (o *CiWorkflowAttributes) GetLastModifiedDate() time.Time`

GetLastModifiedDate returns the LastModifiedDate field if non-nil, zero value otherwise.

### GetLastModifiedDateOk

`func (o *CiWorkflowAttributes) GetLastModifiedDateOk() (*time.Time, bool)`

GetLastModifiedDateOk returns a tuple with the LastModifiedDate field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLastModifiedDate

`func (o *CiWorkflowAttributes) SetLastModifiedDate(v time.Time)`

SetLastModifiedDate sets LastModifiedDate field to given value.

### HasLastModifiedDate

`func (o *CiWorkflowAttributes) HasLastModifiedDate() bool`

HasLastModifiedDate returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


