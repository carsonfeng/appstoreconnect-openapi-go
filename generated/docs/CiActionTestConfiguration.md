# CiActionTestConfiguration

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Kind** | Pointer to **string** |  | [optional] 
**TestPlanName** | Pointer to **string** |  | [optional] 
**TestDestinations** | Pointer to [**[]CiTestDestination**](CiTestDestination.md) |  | [optional] 

## Methods

### NewCiActionTestConfiguration

`func NewCiActionTestConfiguration() *CiActionTestConfiguration`

NewCiActionTestConfiguration instantiates a new CiActionTestConfiguration object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCiActionTestConfigurationWithDefaults

`func NewCiActionTestConfigurationWithDefaults() *CiActionTestConfiguration`

NewCiActionTestConfigurationWithDefaults instantiates a new CiActionTestConfiguration object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetKind

`func (o *CiActionTestConfiguration) GetKind() string`

GetKind returns the Kind field if non-nil, zero value otherwise.

### GetKindOk

`func (o *CiActionTestConfiguration) GetKindOk() (*string, bool)`

GetKindOk returns a tuple with the Kind field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetKind

`func (o *CiActionTestConfiguration) SetKind(v string)`

SetKind sets Kind field to given value.

### HasKind

`func (o *CiActionTestConfiguration) HasKind() bool`

HasKind returns a boolean if a field has been set.

### GetTestPlanName

`func (o *CiActionTestConfiguration) GetTestPlanName() string`

GetTestPlanName returns the TestPlanName field if non-nil, zero value otherwise.

### GetTestPlanNameOk

`func (o *CiActionTestConfiguration) GetTestPlanNameOk() (*string, bool)`

GetTestPlanNameOk returns a tuple with the TestPlanName field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTestPlanName

`func (o *CiActionTestConfiguration) SetTestPlanName(v string)`

SetTestPlanName sets TestPlanName field to given value.

### HasTestPlanName

`func (o *CiActionTestConfiguration) HasTestPlanName() bool`

HasTestPlanName returns a boolean if a field has been set.

### GetTestDestinations

`func (o *CiActionTestConfiguration) GetTestDestinations() []CiTestDestination`

GetTestDestinations returns the TestDestinations field if non-nil, zero value otherwise.

### GetTestDestinationsOk

`func (o *CiActionTestConfiguration) GetTestDestinationsOk() (*[]CiTestDestination, bool)`

GetTestDestinationsOk returns a tuple with the TestDestinations field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTestDestinations

`func (o *CiActionTestConfiguration) SetTestDestinations(v []CiTestDestination)`

SetTestDestinations sets TestDestinations field to given value.

### HasTestDestinations

`func (o *CiActionTestConfiguration) HasTestDestinations() bool`

HasTestDestinations returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


