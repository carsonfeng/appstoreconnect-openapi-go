# CiBuildRun

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**CiBuildRunAttributes**](CiBuildRunAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**CiBuildRunRelationships**](CiBuildRunRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewCiBuildRun

`func NewCiBuildRun(type_ string, id string, links ResourceLinks, ) *CiBuildRun`

NewCiBuildRun instantiates a new CiBuildRun object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCiBuildRunWithDefaults

`func NewCiBuildRunWithDefaults() *CiBuildRun`

NewCiBuildRunWithDefaults instantiates a new CiBuildRun object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *CiBuildRun) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *CiBuildRun) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *CiBuildRun) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *CiBuildRun) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *CiBuildRun) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *CiBuildRun) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *CiBuildRun) GetAttributes() CiBuildRunAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *CiBuildRun) GetAttributesOk() (*CiBuildRunAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *CiBuildRun) SetAttributes(v CiBuildRunAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *CiBuildRun) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *CiBuildRun) GetRelationships() CiBuildRunRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *CiBuildRun) GetRelationshipsOk() (*CiBuildRunRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *CiBuildRun) SetRelationships(v CiBuildRunRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *CiBuildRun) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *CiBuildRun) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *CiBuildRun) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *CiBuildRun) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


