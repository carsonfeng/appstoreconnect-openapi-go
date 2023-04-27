# AppClipDefaultExperienceCreateRequestData

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Attributes** | Pointer to [**AppClipDefaultExperienceAttributes**](AppClipDefaultExperienceAttributes.md) |  | [optional] 
**Relationships** | [**AppClipDefaultExperienceCreateRequestDataRelationships**](AppClipDefaultExperienceCreateRequestDataRelationships.md) |  | 

## Methods

### NewAppClipDefaultExperienceCreateRequestData

`func NewAppClipDefaultExperienceCreateRequestData(type_ string, relationships AppClipDefaultExperienceCreateRequestDataRelationships, ) *AppClipDefaultExperienceCreateRequestData`

NewAppClipDefaultExperienceCreateRequestData instantiates a new AppClipDefaultExperienceCreateRequestData object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppClipDefaultExperienceCreateRequestDataWithDefaults

`func NewAppClipDefaultExperienceCreateRequestDataWithDefaults() *AppClipDefaultExperienceCreateRequestData`

NewAppClipDefaultExperienceCreateRequestDataWithDefaults instantiates a new AppClipDefaultExperienceCreateRequestData object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *AppClipDefaultExperienceCreateRequestData) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *AppClipDefaultExperienceCreateRequestData) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *AppClipDefaultExperienceCreateRequestData) SetType(v string)`

SetType sets Type field to given value.


### GetAttributes

`func (o *AppClipDefaultExperienceCreateRequestData) GetAttributes() AppClipDefaultExperienceAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *AppClipDefaultExperienceCreateRequestData) GetAttributesOk() (*AppClipDefaultExperienceAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *AppClipDefaultExperienceCreateRequestData) SetAttributes(v AppClipDefaultExperienceAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *AppClipDefaultExperienceCreateRequestData) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *AppClipDefaultExperienceCreateRequestData) GetRelationships() AppClipDefaultExperienceCreateRequestDataRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *AppClipDefaultExperienceCreateRequestData) GetRelationshipsOk() (*AppClipDefaultExperienceCreateRequestDataRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *AppClipDefaultExperienceCreateRequestData) SetRelationships(v AppClipDefaultExperienceCreateRequestDataRelationships)`

SetRelationships sets Relationships field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


