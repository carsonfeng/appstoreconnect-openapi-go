# BuildBundle

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**BuildBundleAttributes**](BuildBundleAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**BuildBundleRelationships**](BuildBundleRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewBuildBundle

`func NewBuildBundle(type_ string, id string, links ResourceLinks, ) *BuildBundle`

NewBuildBundle instantiates a new BuildBundle object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewBuildBundleWithDefaults

`func NewBuildBundleWithDefaults() *BuildBundle`

NewBuildBundleWithDefaults instantiates a new BuildBundle object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *BuildBundle) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *BuildBundle) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *BuildBundle) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *BuildBundle) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *BuildBundle) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *BuildBundle) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *BuildBundle) GetAttributes() BuildBundleAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *BuildBundle) GetAttributesOk() (*BuildBundleAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *BuildBundle) SetAttributes(v BuildBundleAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *BuildBundle) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *BuildBundle) GetRelationships() BuildBundleRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *BuildBundle) GetRelationshipsOk() (*BuildBundleRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *BuildBundle) SetRelationships(v BuildBundleRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *BuildBundle) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *BuildBundle) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *BuildBundle) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *BuildBundle) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


