# AppStoreVersionsResponseIncludedInner

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**AppStoreVersionExperimentAttributes**](AppStoreVersionExperimentAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**AppStoreVersionExperimentRelationships**](AppStoreVersionExperimentRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewAppStoreVersionsResponseIncludedInner

`func NewAppStoreVersionsResponseIncludedInner(type_ string, id string, links ResourceLinks, ) *AppStoreVersionsResponseIncludedInner`

NewAppStoreVersionsResponseIncludedInner instantiates a new AppStoreVersionsResponseIncludedInner object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppStoreVersionsResponseIncludedInnerWithDefaults

`func NewAppStoreVersionsResponseIncludedInnerWithDefaults() *AppStoreVersionsResponseIncludedInner`

NewAppStoreVersionsResponseIncludedInnerWithDefaults instantiates a new AppStoreVersionsResponseIncludedInner object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *AppStoreVersionsResponseIncludedInner) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *AppStoreVersionsResponseIncludedInner) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *AppStoreVersionsResponseIncludedInner) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *AppStoreVersionsResponseIncludedInner) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *AppStoreVersionsResponseIncludedInner) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *AppStoreVersionsResponseIncludedInner) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *AppStoreVersionsResponseIncludedInner) GetAttributes() AppStoreVersionExperimentAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *AppStoreVersionsResponseIncludedInner) GetAttributesOk() (*AppStoreVersionExperimentAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *AppStoreVersionsResponseIncludedInner) SetAttributes(v AppStoreVersionExperimentAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *AppStoreVersionsResponseIncludedInner) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *AppStoreVersionsResponseIncludedInner) GetRelationships() AppStoreVersionExperimentRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *AppStoreVersionsResponseIncludedInner) GetRelationshipsOk() (*AppStoreVersionExperimentRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *AppStoreVersionsResponseIncludedInner) SetRelationships(v AppStoreVersionExperimentRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *AppStoreVersionsResponseIncludedInner) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *AppStoreVersionsResponseIncludedInner) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppStoreVersionsResponseIncludedInner) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppStoreVersionsResponseIncludedInner) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


