# CiAction

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Name** | Pointer to **string** |  | [optional] 
**ActionType** | Pointer to [**CiActionType**](CiActionType.md) |  | [optional] 
**Destination** | Pointer to **string** |  | [optional] 
**BuildDistributionAudience** | Pointer to [**BuildAudienceType**](BuildAudienceType.md) |  | [optional] 
**TestConfiguration** | Pointer to [**CiActionTestConfiguration**](CiActionTestConfiguration.md) |  | [optional] 
**Scheme** | Pointer to **string** |  | [optional] 
**Platform** | Pointer to **string** |  | [optional] 
**IsRequiredToPass** | Pointer to **bool** |  | [optional] 

## Methods

### NewCiAction

`func NewCiAction() *CiAction`

NewCiAction instantiates a new CiAction object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCiActionWithDefaults

`func NewCiActionWithDefaults() *CiAction`

NewCiActionWithDefaults instantiates a new CiAction object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetName

`func (o *CiAction) GetName() string`

GetName returns the Name field if non-nil, zero value otherwise.

### GetNameOk

`func (o *CiAction) GetNameOk() (*string, bool)`

GetNameOk returns a tuple with the Name field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetName

`func (o *CiAction) SetName(v string)`

SetName sets Name field to given value.

### HasName

`func (o *CiAction) HasName() bool`

HasName returns a boolean if a field has been set.

### GetActionType

`func (o *CiAction) GetActionType() CiActionType`

GetActionType returns the ActionType field if non-nil, zero value otherwise.

### GetActionTypeOk

`func (o *CiAction) GetActionTypeOk() (*CiActionType, bool)`

GetActionTypeOk returns a tuple with the ActionType field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetActionType

`func (o *CiAction) SetActionType(v CiActionType)`

SetActionType sets ActionType field to given value.

### HasActionType

`func (o *CiAction) HasActionType() bool`

HasActionType returns a boolean if a field has been set.

### GetDestination

`func (o *CiAction) GetDestination() string`

GetDestination returns the Destination field if non-nil, zero value otherwise.

### GetDestinationOk

`func (o *CiAction) GetDestinationOk() (*string, bool)`

GetDestinationOk returns a tuple with the Destination field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDestination

`func (o *CiAction) SetDestination(v string)`

SetDestination sets Destination field to given value.

### HasDestination

`func (o *CiAction) HasDestination() bool`

HasDestination returns a boolean if a field has been set.

### GetBuildDistributionAudience

`func (o *CiAction) GetBuildDistributionAudience() BuildAudienceType`

GetBuildDistributionAudience returns the BuildDistributionAudience field if non-nil, zero value otherwise.

### GetBuildDistributionAudienceOk

`func (o *CiAction) GetBuildDistributionAudienceOk() (*BuildAudienceType, bool)`

GetBuildDistributionAudienceOk returns a tuple with the BuildDistributionAudience field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetBuildDistributionAudience

`func (o *CiAction) SetBuildDistributionAudience(v BuildAudienceType)`

SetBuildDistributionAudience sets BuildDistributionAudience field to given value.

### HasBuildDistributionAudience

`func (o *CiAction) HasBuildDistributionAudience() bool`

HasBuildDistributionAudience returns a boolean if a field has been set.

### GetTestConfiguration

`func (o *CiAction) GetTestConfiguration() CiActionTestConfiguration`

GetTestConfiguration returns the TestConfiguration field if non-nil, zero value otherwise.

### GetTestConfigurationOk

`func (o *CiAction) GetTestConfigurationOk() (*CiActionTestConfiguration, bool)`

GetTestConfigurationOk returns a tuple with the TestConfiguration field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTestConfiguration

`func (o *CiAction) SetTestConfiguration(v CiActionTestConfiguration)`

SetTestConfiguration sets TestConfiguration field to given value.

### HasTestConfiguration

`func (o *CiAction) HasTestConfiguration() bool`

HasTestConfiguration returns a boolean if a field has been set.

### GetScheme

`func (o *CiAction) GetScheme() string`

GetScheme returns the Scheme field if non-nil, zero value otherwise.

### GetSchemeOk

`func (o *CiAction) GetSchemeOk() (*string, bool)`

GetSchemeOk returns a tuple with the Scheme field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetScheme

`func (o *CiAction) SetScheme(v string)`

SetScheme sets Scheme field to given value.

### HasScheme

`func (o *CiAction) HasScheme() bool`

HasScheme returns a boolean if a field has been set.

### GetPlatform

`func (o *CiAction) GetPlatform() string`

GetPlatform returns the Platform field if non-nil, zero value otherwise.

### GetPlatformOk

`func (o *CiAction) GetPlatformOk() (*string, bool)`

GetPlatformOk returns a tuple with the Platform field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPlatform

`func (o *CiAction) SetPlatform(v string)`

SetPlatform sets Platform field to given value.

### HasPlatform

`func (o *CiAction) HasPlatform() bool`

HasPlatform returns a boolean if a field has been set.

### GetIsRequiredToPass

`func (o *CiAction) GetIsRequiredToPass() bool`

GetIsRequiredToPass returns the IsRequiredToPass field if non-nil, zero value otherwise.

### GetIsRequiredToPassOk

`func (o *CiAction) GetIsRequiredToPassOk() (*bool, bool)`

GetIsRequiredToPassOk returns a tuple with the IsRequiredToPass field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIsRequiredToPass

`func (o *CiAction) SetIsRequiredToPass(v bool)`

SetIsRequiredToPass sets IsRequiredToPass field to given value.

### HasIsRequiredToPass

`func (o *CiAction) HasIsRequiredToPass() bool`

HasIsRequiredToPass returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


