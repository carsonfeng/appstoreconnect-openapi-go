# AppClipDefaultExperience

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**AppClipDefaultExperienceAttributes**](AppClipDefaultExperienceAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**AppClipDefaultExperienceRelationships**](AppClipDefaultExperienceRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewAppClipDefaultExperience

`func NewAppClipDefaultExperience(type_ string, id string, links ResourceLinks, ) *AppClipDefaultExperience`

NewAppClipDefaultExperience instantiates a new AppClipDefaultExperience object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppClipDefaultExperienceWithDefaults

`func NewAppClipDefaultExperienceWithDefaults() *AppClipDefaultExperience`

NewAppClipDefaultExperienceWithDefaults instantiates a new AppClipDefaultExperience object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *AppClipDefaultExperience) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *AppClipDefaultExperience) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *AppClipDefaultExperience) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *AppClipDefaultExperience) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *AppClipDefaultExperience) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *AppClipDefaultExperience) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *AppClipDefaultExperience) GetAttributes() AppClipDefaultExperienceAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *AppClipDefaultExperience) GetAttributesOk() (*AppClipDefaultExperienceAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *AppClipDefaultExperience) SetAttributes(v AppClipDefaultExperienceAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *AppClipDefaultExperience) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *AppClipDefaultExperience) GetRelationships() AppClipDefaultExperienceRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *AppClipDefaultExperience) GetRelationshipsOk() (*AppClipDefaultExperienceRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *AppClipDefaultExperience) SetRelationships(v AppClipDefaultExperienceRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *AppClipDefaultExperience) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *AppClipDefaultExperience) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppClipDefaultExperience) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppClipDefaultExperience) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


