# GameCenterEnabledVersionsResponseIncludedInner

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**AppAttributes**](AppAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**AppRelationships**](AppRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewGameCenterEnabledVersionsResponseIncludedInner

`func NewGameCenterEnabledVersionsResponseIncludedInner(type_ string, id string, links ResourceLinks, ) *GameCenterEnabledVersionsResponseIncludedInner`

NewGameCenterEnabledVersionsResponseIncludedInner instantiates a new GameCenterEnabledVersionsResponseIncludedInner object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewGameCenterEnabledVersionsResponseIncludedInnerWithDefaults

`func NewGameCenterEnabledVersionsResponseIncludedInnerWithDefaults() *GameCenterEnabledVersionsResponseIncludedInner`

NewGameCenterEnabledVersionsResponseIncludedInnerWithDefaults instantiates a new GameCenterEnabledVersionsResponseIncludedInner object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *GameCenterEnabledVersionsResponseIncludedInner) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *GameCenterEnabledVersionsResponseIncludedInner) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *GameCenterEnabledVersionsResponseIncludedInner) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *GameCenterEnabledVersionsResponseIncludedInner) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *GameCenterEnabledVersionsResponseIncludedInner) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *GameCenterEnabledVersionsResponseIncludedInner) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *GameCenterEnabledVersionsResponseIncludedInner) GetAttributes() AppAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *GameCenterEnabledVersionsResponseIncludedInner) GetAttributesOk() (*AppAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *GameCenterEnabledVersionsResponseIncludedInner) SetAttributes(v AppAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *GameCenterEnabledVersionsResponseIncludedInner) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *GameCenterEnabledVersionsResponseIncludedInner) GetRelationships() AppRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *GameCenterEnabledVersionsResponseIncludedInner) GetRelationshipsOk() (*AppRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *GameCenterEnabledVersionsResponseIncludedInner) SetRelationships(v AppRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *GameCenterEnabledVersionsResponseIncludedInner) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *GameCenterEnabledVersionsResponseIncludedInner) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *GameCenterEnabledVersionsResponseIncludedInner) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *GameCenterEnabledVersionsResponseIncludedInner) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


