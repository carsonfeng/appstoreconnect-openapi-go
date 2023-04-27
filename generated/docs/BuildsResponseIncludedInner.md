# BuildsResponseIncludedInner

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**BuildBundleAttributes**](BuildBundleAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**BuildBundleRelationships**](BuildBundleRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewBuildsResponseIncludedInner

`func NewBuildsResponseIncludedInner(type_ string, id string, links ResourceLinks, ) *BuildsResponseIncludedInner`

NewBuildsResponseIncludedInner instantiates a new BuildsResponseIncludedInner object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewBuildsResponseIncludedInnerWithDefaults

`func NewBuildsResponseIncludedInnerWithDefaults() *BuildsResponseIncludedInner`

NewBuildsResponseIncludedInnerWithDefaults instantiates a new BuildsResponseIncludedInner object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *BuildsResponseIncludedInner) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *BuildsResponseIncludedInner) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *BuildsResponseIncludedInner) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *BuildsResponseIncludedInner) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *BuildsResponseIncludedInner) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *BuildsResponseIncludedInner) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *BuildsResponseIncludedInner) GetAttributes() BuildBundleAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *BuildsResponseIncludedInner) GetAttributesOk() (*BuildBundleAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *BuildsResponseIncludedInner) SetAttributes(v BuildBundleAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *BuildsResponseIncludedInner) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *BuildsResponseIncludedInner) GetRelationships() BuildBundleRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *BuildsResponseIncludedInner) GetRelationshipsOk() (*BuildBundleRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *BuildsResponseIncludedInner) SetRelationships(v BuildBundleRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *BuildsResponseIncludedInner) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *BuildsResponseIncludedInner) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *BuildsResponseIncludedInner) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *BuildsResponseIncludedInner) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


