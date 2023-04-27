# CiWorkflowRelationships

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Product** | Pointer to [**AppRelationshipsCiProduct**](AppRelationshipsCiProduct.md) |  | [optional] 
**Repository** | Pointer to [**CiWorkflowRelationshipsRepository**](CiWorkflowRelationshipsRepository.md) |  | [optional] 
**XcodeVersion** | Pointer to [**CiWorkflowRelationshipsXcodeVersion**](CiWorkflowRelationshipsXcodeVersion.md) |  | [optional] 
**MacOsVersion** | Pointer to [**CiWorkflowRelationshipsMacOsVersion**](CiWorkflowRelationshipsMacOsVersion.md) |  | [optional] 

## Methods

### NewCiWorkflowRelationships

`func NewCiWorkflowRelationships() *CiWorkflowRelationships`

NewCiWorkflowRelationships instantiates a new CiWorkflowRelationships object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCiWorkflowRelationshipsWithDefaults

`func NewCiWorkflowRelationshipsWithDefaults() *CiWorkflowRelationships`

NewCiWorkflowRelationshipsWithDefaults instantiates a new CiWorkflowRelationships object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetProduct

`func (o *CiWorkflowRelationships) GetProduct() AppRelationshipsCiProduct`

GetProduct returns the Product field if non-nil, zero value otherwise.

### GetProductOk

`func (o *CiWorkflowRelationships) GetProductOk() (*AppRelationshipsCiProduct, bool)`

GetProductOk returns a tuple with the Product field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetProduct

`func (o *CiWorkflowRelationships) SetProduct(v AppRelationshipsCiProduct)`

SetProduct sets Product field to given value.

### HasProduct

`func (o *CiWorkflowRelationships) HasProduct() bool`

HasProduct returns a boolean if a field has been set.

### GetRepository

`func (o *CiWorkflowRelationships) GetRepository() CiWorkflowRelationshipsRepository`

GetRepository returns the Repository field if non-nil, zero value otherwise.

### GetRepositoryOk

`func (o *CiWorkflowRelationships) GetRepositoryOk() (*CiWorkflowRelationshipsRepository, bool)`

GetRepositoryOk returns a tuple with the Repository field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRepository

`func (o *CiWorkflowRelationships) SetRepository(v CiWorkflowRelationshipsRepository)`

SetRepository sets Repository field to given value.

### HasRepository

`func (o *CiWorkflowRelationships) HasRepository() bool`

HasRepository returns a boolean if a field has been set.

### GetXcodeVersion

`func (o *CiWorkflowRelationships) GetXcodeVersion() CiWorkflowRelationshipsXcodeVersion`

GetXcodeVersion returns the XcodeVersion field if non-nil, zero value otherwise.

### GetXcodeVersionOk

`func (o *CiWorkflowRelationships) GetXcodeVersionOk() (*CiWorkflowRelationshipsXcodeVersion, bool)`

GetXcodeVersionOk returns a tuple with the XcodeVersion field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetXcodeVersion

`func (o *CiWorkflowRelationships) SetXcodeVersion(v CiWorkflowRelationshipsXcodeVersion)`

SetXcodeVersion sets XcodeVersion field to given value.

### HasXcodeVersion

`func (o *CiWorkflowRelationships) HasXcodeVersion() bool`

HasXcodeVersion returns a boolean if a field has been set.

### GetMacOsVersion

`func (o *CiWorkflowRelationships) GetMacOsVersion() CiWorkflowRelationshipsMacOsVersion`

GetMacOsVersion returns the MacOsVersion field if non-nil, zero value otherwise.

### GetMacOsVersionOk

`func (o *CiWorkflowRelationships) GetMacOsVersionOk() (*CiWorkflowRelationshipsMacOsVersion, bool)`

GetMacOsVersionOk returns a tuple with the MacOsVersion field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMacOsVersion

`func (o *CiWorkflowRelationships) SetMacOsVersion(v CiWorkflowRelationshipsMacOsVersion)`

SetMacOsVersion sets MacOsVersion field to given value.

### HasMacOsVersion

`func (o *CiWorkflowRelationships) HasMacOsVersion() bool`

HasMacOsVersion returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


