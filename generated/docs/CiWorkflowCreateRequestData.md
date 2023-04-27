# CiWorkflowCreateRequestData

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Attributes** | [**CiWorkflowCreateRequestDataAttributes**](CiWorkflowCreateRequestDataAttributes.md) |  | 
**Relationships** | [**CiWorkflowCreateRequestDataRelationships**](CiWorkflowCreateRequestDataRelationships.md) |  | 

## Methods

### NewCiWorkflowCreateRequestData

`func NewCiWorkflowCreateRequestData(type_ string, attributes CiWorkflowCreateRequestDataAttributes, relationships CiWorkflowCreateRequestDataRelationships, ) *CiWorkflowCreateRequestData`

NewCiWorkflowCreateRequestData instantiates a new CiWorkflowCreateRequestData object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCiWorkflowCreateRequestDataWithDefaults

`func NewCiWorkflowCreateRequestDataWithDefaults() *CiWorkflowCreateRequestData`

NewCiWorkflowCreateRequestDataWithDefaults instantiates a new CiWorkflowCreateRequestData object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *CiWorkflowCreateRequestData) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *CiWorkflowCreateRequestData) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *CiWorkflowCreateRequestData) SetType(v string)`

SetType sets Type field to given value.


### GetAttributes

`func (o *CiWorkflowCreateRequestData) GetAttributes() CiWorkflowCreateRequestDataAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *CiWorkflowCreateRequestData) GetAttributesOk() (*CiWorkflowCreateRequestDataAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *CiWorkflowCreateRequestData) SetAttributes(v CiWorkflowCreateRequestDataAttributes)`

SetAttributes sets Attributes field to given value.


### GetRelationships

`func (o *CiWorkflowCreateRequestData) GetRelationships() CiWorkflowCreateRequestDataRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *CiWorkflowCreateRequestData) GetRelationshipsOk() (*CiWorkflowCreateRequestDataRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *CiWorkflowCreateRequestData) SetRelationships(v CiWorkflowCreateRequestDataRelationships)`

SetRelationships sets Relationships field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


