# CiXcodeVersionAttributes

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Version** | Pointer to **string** |  | [optional] 
**Name** | Pointer to **string** |  | [optional] 
**TestDestinations** | Pointer to [**[]CiXcodeVersionAttributesTestDestinationsInner**](CiXcodeVersionAttributesTestDestinationsInner.md) |  | [optional] 

## Methods

### NewCiXcodeVersionAttributes

`func NewCiXcodeVersionAttributes() *CiXcodeVersionAttributes`

NewCiXcodeVersionAttributes instantiates a new CiXcodeVersionAttributes object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCiXcodeVersionAttributesWithDefaults

`func NewCiXcodeVersionAttributesWithDefaults() *CiXcodeVersionAttributes`

NewCiXcodeVersionAttributesWithDefaults instantiates a new CiXcodeVersionAttributes object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetVersion

`func (o *CiXcodeVersionAttributes) GetVersion() string`

GetVersion returns the Version field if non-nil, zero value otherwise.

### GetVersionOk

`func (o *CiXcodeVersionAttributes) GetVersionOk() (*string, bool)`

GetVersionOk returns a tuple with the Version field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetVersion

`func (o *CiXcodeVersionAttributes) SetVersion(v string)`

SetVersion sets Version field to given value.

### HasVersion

`func (o *CiXcodeVersionAttributes) HasVersion() bool`

HasVersion returns a boolean if a field has been set.

### GetName

`func (o *CiXcodeVersionAttributes) GetName() string`

GetName returns the Name field if non-nil, zero value otherwise.

### GetNameOk

`func (o *CiXcodeVersionAttributes) GetNameOk() (*string, bool)`

GetNameOk returns a tuple with the Name field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetName

`func (o *CiXcodeVersionAttributes) SetName(v string)`

SetName sets Name field to given value.

### HasName

`func (o *CiXcodeVersionAttributes) HasName() bool`

HasName returns a boolean if a field has been set.

### GetTestDestinations

`func (o *CiXcodeVersionAttributes) GetTestDestinations() []CiXcodeVersionAttributesTestDestinationsInner`

GetTestDestinations returns the TestDestinations field if non-nil, zero value otherwise.

### GetTestDestinationsOk

`func (o *CiXcodeVersionAttributes) GetTestDestinationsOk() (*[]CiXcodeVersionAttributesTestDestinationsInner, bool)`

GetTestDestinationsOk returns a tuple with the TestDestinations field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTestDestinations

`func (o *CiXcodeVersionAttributes) SetTestDestinations(v []CiXcodeVersionAttributesTestDestinationsInner)`

SetTestDestinations sets TestDestinations field to given value.

### HasTestDestinations

`func (o *CiXcodeVersionAttributes) HasTestDestinations() bool`

HasTestDestinations returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


