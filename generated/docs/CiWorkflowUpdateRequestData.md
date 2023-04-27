# CiWorkflowUpdateRequestData

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**CiWorkflowUpdateRequestDataAttributes**](CiWorkflowUpdateRequestDataAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**CiWorkflowUpdateRequestDataRelationships**](CiWorkflowUpdateRequestDataRelationships.md) |  | [optional] 

## Methods

### NewCiWorkflowUpdateRequestData

`func NewCiWorkflowUpdateRequestData(type_ string, id string, ) *CiWorkflowUpdateRequestData`

NewCiWorkflowUpdateRequestData instantiates a new CiWorkflowUpdateRequestData object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCiWorkflowUpdateRequestDataWithDefaults

`func NewCiWorkflowUpdateRequestDataWithDefaults() *CiWorkflowUpdateRequestData`

NewCiWorkflowUpdateRequestDataWithDefaults instantiates a new CiWorkflowUpdateRequestData object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *CiWorkflowUpdateRequestData) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *CiWorkflowUpdateRequestData) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *CiWorkflowUpdateRequestData) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *CiWorkflowUpdateRequestData) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *CiWorkflowUpdateRequestData) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *CiWorkflowUpdateRequestData) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *CiWorkflowUpdateRequestData) GetAttributes() CiWorkflowUpdateRequestDataAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *CiWorkflowUpdateRequestData) GetAttributesOk() (*CiWorkflowUpdateRequestDataAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *CiWorkflowUpdateRequestData) SetAttributes(v CiWorkflowUpdateRequestDataAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *CiWorkflowUpdateRequestData) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *CiWorkflowUpdateRequestData) GetRelationships() CiWorkflowUpdateRequestDataRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *CiWorkflowUpdateRequestData) GetRelationshipsOk() (*CiWorkflowUpdateRequestDataRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *CiWorkflowUpdateRequestData) SetRelationships(v CiWorkflowUpdateRequestDataRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *CiWorkflowUpdateRequestData) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


