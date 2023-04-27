# CiWorkflow

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**CiWorkflowAttributes**](CiWorkflowAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**CiWorkflowRelationships**](CiWorkflowRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewCiWorkflow

`func NewCiWorkflow(type_ string, id string, links ResourceLinks, ) *CiWorkflow`

NewCiWorkflow instantiates a new CiWorkflow object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCiWorkflowWithDefaults

`func NewCiWorkflowWithDefaults() *CiWorkflow`

NewCiWorkflowWithDefaults instantiates a new CiWorkflow object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *CiWorkflow) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *CiWorkflow) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *CiWorkflow) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *CiWorkflow) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *CiWorkflow) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *CiWorkflow) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *CiWorkflow) GetAttributes() CiWorkflowAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *CiWorkflow) GetAttributesOk() (*CiWorkflowAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *CiWorkflow) SetAttributes(v CiWorkflowAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *CiWorkflow) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *CiWorkflow) GetRelationships() CiWorkflowRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *CiWorkflow) GetRelationshipsOk() (*CiWorkflowRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *CiWorkflow) SetRelationships(v CiWorkflowRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *CiWorkflow) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *CiWorkflow) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *CiWorkflow) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *CiWorkflow) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


