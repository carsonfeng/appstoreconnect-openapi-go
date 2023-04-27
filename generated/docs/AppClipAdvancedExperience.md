# AppClipAdvancedExperience

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**AppClipAdvancedExperienceAttributes**](AppClipAdvancedExperienceAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**AppClipAdvancedExperienceRelationships**](AppClipAdvancedExperienceRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewAppClipAdvancedExperience

`func NewAppClipAdvancedExperience(type_ string, id string, links ResourceLinks, ) *AppClipAdvancedExperience`

NewAppClipAdvancedExperience instantiates a new AppClipAdvancedExperience object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppClipAdvancedExperienceWithDefaults

`func NewAppClipAdvancedExperienceWithDefaults() *AppClipAdvancedExperience`

NewAppClipAdvancedExperienceWithDefaults instantiates a new AppClipAdvancedExperience object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *AppClipAdvancedExperience) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *AppClipAdvancedExperience) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *AppClipAdvancedExperience) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *AppClipAdvancedExperience) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *AppClipAdvancedExperience) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *AppClipAdvancedExperience) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *AppClipAdvancedExperience) GetAttributes() AppClipAdvancedExperienceAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *AppClipAdvancedExperience) GetAttributesOk() (*AppClipAdvancedExperienceAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *AppClipAdvancedExperience) SetAttributes(v AppClipAdvancedExperienceAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *AppClipAdvancedExperience) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *AppClipAdvancedExperience) GetRelationships() AppClipAdvancedExperienceRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *AppClipAdvancedExperience) GetRelationshipsOk() (*AppClipAdvancedExperienceRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *AppClipAdvancedExperience) SetRelationships(v AppClipAdvancedExperienceRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *AppClipAdvancedExperience) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *AppClipAdvancedExperience) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppClipAdvancedExperience) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppClipAdvancedExperience) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


