# AppClipsResponseIncludedInner

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**AppClipDefaultExperienceAttributes**](AppClipDefaultExperienceAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**AppClipDefaultExperienceRelationships**](AppClipDefaultExperienceRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewAppClipsResponseIncludedInner

`func NewAppClipsResponseIncludedInner(type_ string, id string, links ResourceLinks, ) *AppClipsResponseIncludedInner`

NewAppClipsResponseIncludedInner instantiates a new AppClipsResponseIncludedInner object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppClipsResponseIncludedInnerWithDefaults

`func NewAppClipsResponseIncludedInnerWithDefaults() *AppClipsResponseIncludedInner`

NewAppClipsResponseIncludedInnerWithDefaults instantiates a new AppClipsResponseIncludedInner object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *AppClipsResponseIncludedInner) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *AppClipsResponseIncludedInner) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *AppClipsResponseIncludedInner) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *AppClipsResponseIncludedInner) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *AppClipsResponseIncludedInner) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *AppClipsResponseIncludedInner) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *AppClipsResponseIncludedInner) GetAttributes() AppClipDefaultExperienceAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *AppClipsResponseIncludedInner) GetAttributesOk() (*AppClipDefaultExperienceAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *AppClipsResponseIncludedInner) SetAttributes(v AppClipDefaultExperienceAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *AppClipsResponseIncludedInner) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *AppClipsResponseIncludedInner) GetRelationships() AppClipDefaultExperienceRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *AppClipsResponseIncludedInner) GetRelationshipsOk() (*AppClipDefaultExperienceRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *AppClipsResponseIncludedInner) SetRelationships(v AppClipDefaultExperienceRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *AppClipsResponseIncludedInner) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *AppClipsResponseIncludedInner) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppClipsResponseIncludedInner) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppClipsResponseIncludedInner) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


