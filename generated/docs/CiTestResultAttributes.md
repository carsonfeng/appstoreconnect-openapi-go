# CiTestResultAttributes

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**ClassName** | Pointer to **string** |  | [optional] 
**Name** | Pointer to **string** |  | [optional] 
**Status** | Pointer to [**CiTestStatus**](CiTestStatus.md) |  | [optional] 
**FileSource** | Pointer to [**FileLocation**](FileLocation.md) |  | [optional] 
**Message** | Pointer to **string** |  | [optional] 
**DestinationTestResults** | Pointer to [**[]CiTestResultAttributesDestinationTestResultsInner**](CiTestResultAttributesDestinationTestResultsInner.md) |  | [optional] 

## Methods

### NewCiTestResultAttributes

`func NewCiTestResultAttributes() *CiTestResultAttributes`

NewCiTestResultAttributes instantiates a new CiTestResultAttributes object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCiTestResultAttributesWithDefaults

`func NewCiTestResultAttributesWithDefaults() *CiTestResultAttributes`

NewCiTestResultAttributesWithDefaults instantiates a new CiTestResultAttributes object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetClassName

`func (o *CiTestResultAttributes) GetClassName() string`

GetClassName returns the ClassName field if non-nil, zero value otherwise.

### GetClassNameOk

`func (o *CiTestResultAttributes) GetClassNameOk() (*string, bool)`

GetClassNameOk returns a tuple with the ClassName field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetClassName

`func (o *CiTestResultAttributes) SetClassName(v string)`

SetClassName sets ClassName field to given value.

### HasClassName

`func (o *CiTestResultAttributes) HasClassName() bool`

HasClassName returns a boolean if a field has been set.

### GetName

`func (o *CiTestResultAttributes) GetName() string`

GetName returns the Name field if non-nil, zero value otherwise.

### GetNameOk

`func (o *CiTestResultAttributes) GetNameOk() (*string, bool)`

GetNameOk returns a tuple with the Name field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetName

`func (o *CiTestResultAttributes) SetName(v string)`

SetName sets Name field to given value.

### HasName

`func (o *CiTestResultAttributes) HasName() bool`

HasName returns a boolean if a field has been set.

### GetStatus

`func (o *CiTestResultAttributes) GetStatus() CiTestStatus`

GetStatus returns the Status field if non-nil, zero value otherwise.

### GetStatusOk

`func (o *CiTestResultAttributes) GetStatusOk() (*CiTestStatus, bool)`

GetStatusOk returns a tuple with the Status field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetStatus

`func (o *CiTestResultAttributes) SetStatus(v CiTestStatus)`

SetStatus sets Status field to given value.

### HasStatus

`func (o *CiTestResultAttributes) HasStatus() bool`

HasStatus returns a boolean if a field has been set.

### GetFileSource

`func (o *CiTestResultAttributes) GetFileSource() FileLocation`

GetFileSource returns the FileSource field if non-nil, zero value otherwise.

### GetFileSourceOk

`func (o *CiTestResultAttributes) GetFileSourceOk() (*FileLocation, bool)`

GetFileSourceOk returns a tuple with the FileSource field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFileSource

`func (o *CiTestResultAttributes) SetFileSource(v FileLocation)`

SetFileSource sets FileSource field to given value.

### HasFileSource

`func (o *CiTestResultAttributes) HasFileSource() bool`

HasFileSource returns a boolean if a field has been set.

### GetMessage

`func (o *CiTestResultAttributes) GetMessage() string`

GetMessage returns the Message field if non-nil, zero value otherwise.

### GetMessageOk

`func (o *CiTestResultAttributes) GetMessageOk() (*string, bool)`

GetMessageOk returns a tuple with the Message field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMessage

`func (o *CiTestResultAttributes) SetMessage(v string)`

SetMessage sets Message field to given value.

### HasMessage

`func (o *CiTestResultAttributes) HasMessage() bool`

HasMessage returns a boolean if a field has been set.

### GetDestinationTestResults

`func (o *CiTestResultAttributes) GetDestinationTestResults() []CiTestResultAttributesDestinationTestResultsInner`

GetDestinationTestResults returns the DestinationTestResults field if non-nil, zero value otherwise.

### GetDestinationTestResultsOk

`func (o *CiTestResultAttributes) GetDestinationTestResultsOk() (*[]CiTestResultAttributesDestinationTestResultsInner, bool)`

GetDestinationTestResultsOk returns a tuple with the DestinationTestResults field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDestinationTestResults

`func (o *CiTestResultAttributes) SetDestinationTestResults(v []CiTestResultAttributesDestinationTestResultsInner)`

SetDestinationTestResults sets DestinationTestResults field to given value.

### HasDestinationTestResults

`func (o *CiTestResultAttributes) HasDestinationTestResults() bool`

HasDestinationTestResults returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


