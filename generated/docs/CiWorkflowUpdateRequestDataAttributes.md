# CiWorkflowUpdateRequestDataAttributes

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

## Methods

### NewCiWorkflowUpdateRequestDataAttributes

`func NewCiWorkflowUpdateRequestDataAttributes() *CiWorkflowUpdateRequestDataAttributes`

NewCiWorkflowUpdateRequestDataAttributes instantiates a new CiWorkflowUpdateRequestDataAttributes object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCiWorkflowUpdateRequestDataAttributesWithDefaults

`func NewCiWorkflowUpdateRequestDataAttributesWithDefaults() *CiWorkflowUpdateRequestDataAttributes`

NewCiWorkflowUpdateRequestDataAttributesWithDefaults instantiates a new CiWorkflowUpdateRequestDataAttributes object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetName

`func (o *CiWorkflowUpdateRequestDataAttributes) GetName() string`

GetName returns the Name field if non-nil, zero value otherwise.

### GetNameOk

`func (o *CiWorkflowUpdateRequestDataAttributes) GetNameOk() (*string, bool)`

GetNameOk returns a tuple with the Name field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetName

`func (o *CiWorkflowUpdateRequestDataAttributes) SetName(v string)`

SetName sets Name field to given value.

### HasName

`func (o *CiWorkflowUpdateRequestDataAttributes) HasName() bool`

HasName returns a boolean if a field has been set.

### GetDescription

`func (o *CiWorkflowUpdateRequestDataAttributes) GetDescription() string`

GetDescription returns the Description field if non-nil, zero value otherwise.

### GetDescriptionOk

`func (o *CiWorkflowUpdateRequestDataAttributes) GetDescriptionOk() (*string, bool)`

GetDescriptionOk returns a tuple with the Description field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDescription

`func (o *CiWorkflowUpdateRequestDataAttributes) SetDescription(v string)`

SetDescription sets Description field to given value.

### HasDescription

`func (o *CiWorkflowUpdateRequestDataAttributes) HasDescription() bool`

HasDescription returns a boolean if a field has been set.

### GetBranchStartCondition

`func (o *CiWorkflowUpdateRequestDataAttributes) GetBranchStartCondition() CiBranchStartCondition`

GetBranchStartCondition returns the BranchStartCondition field if non-nil, zero value otherwise.

### GetBranchStartConditionOk

`func (o *CiWorkflowUpdateRequestDataAttributes) GetBranchStartConditionOk() (*CiBranchStartCondition, bool)`

GetBranchStartConditionOk returns a tuple with the BranchStartCondition field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetBranchStartCondition

`func (o *CiWorkflowUpdateRequestDataAttributes) SetBranchStartCondition(v CiBranchStartCondition)`

SetBranchStartCondition sets BranchStartCondition field to given value.

### HasBranchStartCondition

`func (o *CiWorkflowUpdateRequestDataAttributes) HasBranchStartCondition() bool`

HasBranchStartCondition returns a boolean if a field has been set.

### GetTagStartCondition

`func (o *CiWorkflowUpdateRequestDataAttributes) GetTagStartCondition() CiTagStartCondition`

GetTagStartCondition returns the TagStartCondition field if non-nil, zero value otherwise.

### GetTagStartConditionOk

`func (o *CiWorkflowUpdateRequestDataAttributes) GetTagStartConditionOk() (*CiTagStartCondition, bool)`

GetTagStartConditionOk returns a tuple with the TagStartCondition field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTagStartCondition

`func (o *CiWorkflowUpdateRequestDataAttributes) SetTagStartCondition(v CiTagStartCondition)`

SetTagStartCondition sets TagStartCondition field to given value.

### HasTagStartCondition

`func (o *CiWorkflowUpdateRequestDataAttributes) HasTagStartCondition() bool`

HasTagStartCondition returns a boolean if a field has been set.

### GetPullRequestStartCondition

`func (o *CiWorkflowUpdateRequestDataAttributes) GetPullRequestStartCondition() CiPullRequestStartCondition`

GetPullRequestStartCondition returns the PullRequestStartCondition field if non-nil, zero value otherwise.

### GetPullRequestStartConditionOk

`func (o *CiWorkflowUpdateRequestDataAttributes) GetPullRequestStartConditionOk() (*CiPullRequestStartCondition, bool)`

GetPullRequestStartConditionOk returns a tuple with the PullRequestStartCondition field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPullRequestStartCondition

`func (o *CiWorkflowUpdateRequestDataAttributes) SetPullRequestStartCondition(v CiPullRequestStartCondition)`

SetPullRequestStartCondition sets PullRequestStartCondition field to given value.

### HasPullRequestStartCondition

`func (o *CiWorkflowUpdateRequestDataAttributes) HasPullRequestStartCondition() bool`

HasPullRequestStartCondition returns a boolean if a field has been set.

### GetScheduledStartCondition

`func (o *CiWorkflowUpdateRequestDataAttributes) GetScheduledStartCondition() CiScheduledStartCondition`

GetScheduledStartCondition returns the ScheduledStartCondition field if non-nil, zero value otherwise.

### GetScheduledStartConditionOk

`func (o *CiWorkflowUpdateRequestDataAttributes) GetScheduledStartConditionOk() (*CiScheduledStartCondition, bool)`

GetScheduledStartConditionOk returns a tuple with the ScheduledStartCondition field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetScheduledStartCondition

`func (o *CiWorkflowUpdateRequestDataAttributes) SetScheduledStartCondition(v CiScheduledStartCondition)`

SetScheduledStartCondition sets ScheduledStartCondition field to given value.

### HasScheduledStartCondition

`func (o *CiWorkflowUpdateRequestDataAttributes) HasScheduledStartCondition() bool`

HasScheduledStartCondition returns a boolean if a field has been set.

### GetActions

`func (o *CiWorkflowUpdateRequestDataAttributes) GetActions() []CiAction`

GetActions returns the Actions field if non-nil, zero value otherwise.

### GetActionsOk

`func (o *CiWorkflowUpdateRequestDataAttributes) GetActionsOk() (*[]CiAction, bool)`

GetActionsOk returns a tuple with the Actions field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetActions

`func (o *CiWorkflowUpdateRequestDataAttributes) SetActions(v []CiAction)`

SetActions sets Actions field to given value.

### HasActions

`func (o *CiWorkflowUpdateRequestDataAttributes) HasActions() bool`

HasActions returns a boolean if a field has been set.

### GetIsEnabled

`func (o *CiWorkflowUpdateRequestDataAttributes) GetIsEnabled() bool`

GetIsEnabled returns the IsEnabled field if non-nil, zero value otherwise.

### GetIsEnabledOk

`func (o *CiWorkflowUpdateRequestDataAttributes) GetIsEnabledOk() (*bool, bool)`

GetIsEnabledOk returns a tuple with the IsEnabled field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIsEnabled

`func (o *CiWorkflowUpdateRequestDataAttributes) SetIsEnabled(v bool)`

SetIsEnabled sets IsEnabled field to given value.

### HasIsEnabled

`func (o *CiWorkflowUpdateRequestDataAttributes) HasIsEnabled() bool`

HasIsEnabled returns a boolean if a field has been set.

### GetIsLockedForEditing

`func (o *CiWorkflowUpdateRequestDataAttributes) GetIsLockedForEditing() bool`

GetIsLockedForEditing returns the IsLockedForEditing field if non-nil, zero value otherwise.

### GetIsLockedForEditingOk

`func (o *CiWorkflowUpdateRequestDataAttributes) GetIsLockedForEditingOk() (*bool, bool)`

GetIsLockedForEditingOk returns a tuple with the IsLockedForEditing field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIsLockedForEditing

`func (o *CiWorkflowUpdateRequestDataAttributes) SetIsLockedForEditing(v bool)`

SetIsLockedForEditing sets IsLockedForEditing field to given value.

### HasIsLockedForEditing

`func (o *CiWorkflowUpdateRequestDataAttributes) HasIsLockedForEditing() bool`

HasIsLockedForEditing returns a boolean if a field has been set.

### GetClean

`func (o *CiWorkflowUpdateRequestDataAttributes) GetClean() bool`

GetClean returns the Clean field if non-nil, zero value otherwise.

### GetCleanOk

`func (o *CiWorkflowUpdateRequestDataAttributes) GetCleanOk() (*bool, bool)`

GetCleanOk returns a tuple with the Clean field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetClean

`func (o *CiWorkflowUpdateRequestDataAttributes) SetClean(v bool)`

SetClean sets Clean field to given value.

### HasClean

`func (o *CiWorkflowUpdateRequestDataAttributes) HasClean() bool`

HasClean returns a boolean if a field has been set.

### GetContainerFilePath

`func (o *CiWorkflowUpdateRequestDataAttributes) GetContainerFilePath() string`

GetContainerFilePath returns the ContainerFilePath field if non-nil, zero value otherwise.

### GetContainerFilePathOk

`func (o *CiWorkflowUpdateRequestDataAttributes) GetContainerFilePathOk() (*string, bool)`

GetContainerFilePathOk returns a tuple with the ContainerFilePath field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetContainerFilePath

`func (o *CiWorkflowUpdateRequestDataAttributes) SetContainerFilePath(v string)`

SetContainerFilePath sets ContainerFilePath field to given value.

### HasContainerFilePath

`func (o *CiWorkflowUpdateRequestDataAttributes) HasContainerFilePath() bool`

HasContainerFilePath returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


