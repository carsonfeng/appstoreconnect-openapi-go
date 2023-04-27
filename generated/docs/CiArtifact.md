# CiArtifact

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**CiArtifactAttributes**](CiArtifactAttributes.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewCiArtifact

`func NewCiArtifact(type_ string, id string, links ResourceLinks, ) *CiArtifact`

NewCiArtifact instantiates a new CiArtifact object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCiArtifactWithDefaults

`func NewCiArtifactWithDefaults() *CiArtifact`

NewCiArtifactWithDefaults instantiates a new CiArtifact object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *CiArtifact) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *CiArtifact) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *CiArtifact) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *CiArtifact) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *CiArtifact) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *CiArtifact) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *CiArtifact) GetAttributes() CiArtifactAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *CiArtifact) GetAttributesOk() (*CiArtifactAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *CiArtifact) SetAttributes(v CiArtifactAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *CiArtifact) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetLinks

`func (o *CiArtifact) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *CiArtifact) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *CiArtifact) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


