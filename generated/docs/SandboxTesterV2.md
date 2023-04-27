# SandboxTesterV2

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**SandboxTesterV2Attributes**](SandboxTesterV2Attributes.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewSandboxTesterV2

`func NewSandboxTesterV2(type_ string, id string, links ResourceLinks, ) *SandboxTesterV2`

NewSandboxTesterV2 instantiates a new SandboxTesterV2 object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSandboxTesterV2WithDefaults

`func NewSandboxTesterV2WithDefaults() *SandboxTesterV2`

NewSandboxTesterV2WithDefaults instantiates a new SandboxTesterV2 object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *SandboxTesterV2) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *SandboxTesterV2) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *SandboxTesterV2) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *SandboxTesterV2) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *SandboxTesterV2) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *SandboxTesterV2) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *SandboxTesterV2) GetAttributes() SandboxTesterV2Attributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *SandboxTesterV2) GetAttributesOk() (*SandboxTesterV2Attributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *SandboxTesterV2) SetAttributes(v SandboxTesterV2Attributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *SandboxTesterV2) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetLinks

`func (o *SandboxTesterV2) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *SandboxTesterV2) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *SandboxTesterV2) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


