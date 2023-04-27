# CiWorkflowCreateRequestDataAttributes

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Name** | **string** |  | 
**Description** | **string** |  | 
**BranchStartCondition** | Pointer to [**CiBranchStartCondition**](CiBranchStartCondition.md) |  | [optional] 
**TagStartCondition** | Pointer to [**CiTagStartCondition**](CiTagStartCondition.md) |  | [optional] 
**PullRequestStartCondition** | Pointer to [**CiPullRequestStartCondition**](CiPullRequestStartCondition.md) |  | [optional] 
**ScheduledStartCondition** | Pointer to [**CiScheduledStartCondition**](CiScheduledStartCondition.md) |  | [optional] 
**Actions** | [**[]CiAction**](CiAction.md) |  | 
**IsEnabled** | **bool** |  | 
**IsLockedForEditing** | Pointer to **bool** |  | [optional] 
**Clean** | **bool** |  | 
**ContainerFilePath** | **string** |  | 

## Methods

### NewCiWorkflowCreateRequestDataAttributes

`func NewCiWorkflowCreateRequestDataAttributes(name string, description string, actions []CiAction, isEnabled bool, clean bool, containerFilePath string, ) *CiWorkflowCreateRequestDataAttributes`

NewCiWorkflowCreateRequestDataAttributes instantiates a new CiWorkflowCreateRequestDataAttributes object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCiWorkflowCreateRequestDataAttributesWithDefaults

`func NewCiWorkflowCreateRequestDataAttributesWithDefaults() *CiWorkflowCreateRequestDataAttributes`

NewCiWorkflowCreateRequestDataAttributesWithDefaults instantiates a new CiWorkflowCreateRequestDataAttributes object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetName

`func (o *CiWorkflowCreateRequestDataAttributes) GetName() string`

GetName returns the Name field if non-nil, zero value otherwise.

### GetNameOk

`func (o *CiWorkflowCreateRequestDataAttributes) GetNameOk() (*string, bool)`

GetNameOk returns a tuple with the Name field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetName

`func (o *CiWorkflowCreateRequestDataAttributes) SetName(v string)`

SetName sets Name field to given value.


### GetDescription

`func (o *CiWorkflowCreateRequestDataAttributes) GetDescription() string`

GetDescription returns the Description field if non-nil, zero value otherwise.

### GetDescriptionOk

`func (o *CiWorkflowCreateRequestDataAttributes) GetDescriptionOk() (*string, bool)`

GetDescriptionOk returns a tuple with the Description field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDescription

`func (o *CiWorkflowCreateRequestDataAttributes) SetDescription(v string)`

SetDescription sets Description field to given value.


### GetBranchStartCondition

`func (o *CiWorkflowCreateRequestDataAttributes) GetBranchStartCondition() CiBranchStartCondition`

GetBranchStartCondition returns the BranchStartCondition field if non-nil, zero value otherwise.

### GetBranchStartConditionOk

`func (o *CiWorkflowCreateRequestDataAttributes) GetBranchStartConditionOk() (*CiBranchStartCondition, bool)`

GetBranchStartConditionOk returns a tuple with the BranchStartCondition field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetBranchStartCondition

`func (o *CiWorkflowCreateRequestDataAttributes) SetBranchStartCondition(v CiBranchStartCondition)`

SetBranchStartCondition sets BranchStartCondition field to given value.

### HasBranchStartCondition

`func (o *CiWorkflowCreateRequestDataAttributes) HasBranchStartCondition() bool`

HasBranchStartCondition returns a boolean if a field has been set.

### GetTagStartCondition

`func (o *CiWorkflowCreateRequestDataAttributes) GetTagStartCondition() CiTagStartCondition`

GetTagStartCondition returns the TagStartCondition field if non-nil, zero value otherwise.

### GetTagStartConditionOk

`func (o *CiWorkflowCreateRequestDataAttributes) GetTagStartConditionOk() (*CiTagStartCondition, bool)`

GetTagStartConditionOk returns a tuple with the TagStartCondition field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTagStartCondition

`func (o *CiWorkflowCreateRequestDataAttributes) SetTagStartCondition(v CiTagStartCondition)`

SetTagStartCondition sets TagStartCondition field to given value.

### HasTagStartCondition

`func (o *CiWorkflowCreateRequestDataAttributes) HasTagStartCondition() bool`

HasTagStartCondition returns a boolean if a field has been set.

### GetPullRequestStartCondition

`func (o *CiWorkflowCreateRequestDataAttributes) GetPullRequestStartCondition() CiPullRequestStartCondition`

GetPullRequestStartCondition returns the PullRequestStartCondition field if non-nil, zero value otherwise.

### GetPullRequestStartConditionOk

`func (o *CiWorkflowCreateRequestDataAttributes) GetPullRequestStartConditionOk() (*CiPullRequestStartCondition, bool)`

GetPullRequestStartConditionOk returns a tuple with the PullRequestStartCondition field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPullRequestStartCondition

`func (o *CiWorkflowCreateRequestDataAttributes) SetPullRequestStartCondition(v CiPullRequestStartCondition)`

SetPullRequestStartCondition sets PullRequestStartCondition field to given value.

### HasPullRequestStartCondition

`func (o *CiWorkflowCreateRequestDataAttributes) HasPullRequestStartCondition() bool`

HasPullRequestStartCondition returns a boolean if a field has been set.

### GetScheduledStartCondition

`func (o *CiWorkflowCreateRequestDataAttributes) GetScheduledStartCondition() CiScheduledStartCondition`

GetScheduledStartCondition returns the ScheduledStartCondition field if non-nil, zero value otherwise.

### GetScheduledStartConditionOk

`func (o *CiWorkflowCreateRequestDataAttributes) GetScheduledStartConditionOk() (*CiScheduledStartCondition, bool)`

GetScheduledStartConditionOk returns a tuple with the ScheduledStartCondition field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetScheduledStartCondition

`func (o *CiWorkflowCreateRequestDataAttributes) SetScheduledStartCondition(v CiScheduledStartCondition)`

SetScheduledStartCondition sets ScheduledStartCondition field to given value.

### HasScheduledStartCondition

`func (o *CiWorkflowCreateRequestDataAttributes) HasScheduledStartCondition() bool`

HasScheduledStartCondition returns a boolean if a field has been set.

### GetActions

`func (o *CiWorkflowCreateRequestDataAttributes) GetActions() []CiAction`

GetActions returns the Actions field if non-nil, zero value otherwise.

### GetActionsOk

`func (o *CiWorkflowCreateRequestDataAttributes) GetActionsOk() (*[]CiAction, bool)`

GetActionsOk returns a tuple with the Actions field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetActions

`func (o *CiWorkflowCreateRequestDataAttributes) SetActions(v []CiAction)`

SetActions sets Actions field to given value.


### GetIsEnabled

`func (o *CiWorkflowCreateRequestDataAttributes) GetIsEnabled() bool`

GetIsEnabled returns the IsEnabled field if non-nil, zero value otherwise.

### GetIsEnabledOk

`func (o *CiWorkflowCreateRequestDataAttributes) GetIsEnabledOk() (*bool, bool)`

GetIsEnabledOk returns a tuple with the IsEnabled field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIsEnabled

`func (o *CiWorkflowCreateRequestDataAttributes) SetIsEnabled(v bool)`

SetIsEnabled sets IsEnabled field to given value.


### GetIsLockedForEditing

`func (o *CiWorkflowCreateRequestDataAttributes) GetIsLockedForEditing() bool`

GetIsLockedForEditing returns the IsLockedForEditing field if non-nil, zero value otherwise.

### GetIsLockedForEditingOk

`func (o *CiWorkflowCreateRequestDataAttributes) GetIsLockedForEditingOk() (*bool, bool)`

GetIsLockedForEditingOk returns a tuple with the IsLockedForEditing field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIsLockedForEditing

`func (o *CiWorkflowCreateRequestDataAttributes) SetIsLockedForEditing(v bool)`

SetIsLockedForEditing sets IsLockedForEditing field to given value.

### HasIsLockedForEditing

`func (o *CiWorkflowCreateRequestDataAttributes) HasIsLockedForEditing() bool`

HasIsLockedForEditing returns a boolean if a field has been set.

### GetClean

`func (o *CiWorkflowCreateRequestDataAttributes) GetClean() bool`

GetClean returns the Clean field if non-nil, zero value otherwise.

### GetCleanOk

`func (o *CiWorkflowCreateRequestDataAttributes) GetCleanOk() (*bool, bool)`

GetCleanOk returns a tuple with the Clean field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetClean

`func (o *CiWorkflowCreateRequestDataAttributes) SetClean(v bool)`

SetClean sets Clean field to given value.


### GetContainerFilePath

`func (o *CiWorkflowCreateRequestDataAttributes) GetContainerFilePath() string`

GetContainerFilePath returns the ContainerFilePath field if non-nil, zero value otherwise.

### GetContainerFilePathOk

`func (o *CiWorkflowCreateRequestDataAttributes) GetContainerFilePathOk() (*string, bool)`

GetContainerFilePathOk returns a tuple with the ContainerFilePath field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetContainerFilePath

`func (o *CiWorkflowCreateRequestDataAttributes) SetContainerFilePath(v string)`

SetContainerFilePath sets ContainerFilePath field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


