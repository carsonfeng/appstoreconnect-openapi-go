# CiXcodeVersion

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**CiXcodeVersionAttributes**](CiXcodeVersionAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**CiXcodeVersionRelationships**](CiXcodeVersionRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewCiXcodeVersion

`func NewCiXcodeVersion(type_ string, id string, links ResourceLinks, ) *CiXcodeVersion`

NewCiXcodeVersion instantiates a new CiXcodeVersion object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCiXcodeVersionWithDefaults

`func NewCiXcodeVersionWithDefaults() *CiXcodeVersion`

NewCiXcodeVersionWithDefaults instantiates a new CiXcodeVersion object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *CiXcodeVersion) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *CiXcodeVersion) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *CiXcodeVersion) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *CiXcodeVersion) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *CiXcodeVersion) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *CiXcodeVersion) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *CiXcodeVersion) GetAttributes() CiXcodeVersionAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *CiXcodeVersion) GetAttributesOk() (*CiXcodeVersionAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *CiXcodeVersion) SetAttributes(v CiXcodeVersionAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *CiXcodeVersion) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *CiXcodeVersion) GetRelationships() CiXcodeVersionRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *CiXcodeVersion) GetRelationshipsOk() (*CiXcodeVersionRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *CiXcodeVersion) SetRelationships(v CiXcodeVersionRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *CiXcodeVersion) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *CiXcodeVersion) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *CiXcodeVersion) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *CiXcodeVersion) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


