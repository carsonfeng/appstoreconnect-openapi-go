# CiMacOsVersion

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**CiMacOsVersionAttributes**](CiMacOsVersionAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**CiMacOsVersionRelationships**](CiMacOsVersionRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewCiMacOsVersion

`func NewCiMacOsVersion(type_ string, id string, links ResourceLinks, ) *CiMacOsVersion`

NewCiMacOsVersion instantiates a new CiMacOsVersion object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCiMacOsVersionWithDefaults

`func NewCiMacOsVersionWithDefaults() *CiMacOsVersion`

NewCiMacOsVersionWithDefaults instantiates a new CiMacOsVersion object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *CiMacOsVersion) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *CiMacOsVersion) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *CiMacOsVersion) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *CiMacOsVersion) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *CiMacOsVersion) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *CiMacOsVersion) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *CiMacOsVersion) GetAttributes() CiMacOsVersionAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *CiMacOsVersion) GetAttributesOk() (*CiMacOsVersionAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *CiMacOsVersion) SetAttributes(v CiMacOsVersionAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *CiMacOsVersion) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *CiMacOsVersion) GetRelationships() CiMacOsVersionRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *CiMacOsVersion) GetRelationshipsOk() (*CiMacOsVersionRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *CiMacOsVersion) SetRelationships(v CiMacOsVersionRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *CiMacOsVersion) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *CiMacOsVersion) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *CiMacOsVersion) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *CiMacOsVersion) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


