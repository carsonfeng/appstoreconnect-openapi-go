# AppStoreVersionExperiment

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**AppStoreVersionExperimentAttributes**](AppStoreVersionExperimentAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**AppStoreVersionExperimentRelationships**](AppStoreVersionExperimentRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewAppStoreVersionExperiment

`func NewAppStoreVersionExperiment(type_ string, id string, links ResourceLinks, ) *AppStoreVersionExperiment`

NewAppStoreVersionExperiment instantiates a new AppStoreVersionExperiment object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppStoreVersionExperimentWithDefaults

`func NewAppStoreVersionExperimentWithDefaults() *AppStoreVersionExperiment`

NewAppStoreVersionExperimentWithDefaults instantiates a new AppStoreVersionExperiment object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *AppStoreVersionExperiment) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *AppStoreVersionExperiment) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *AppStoreVersionExperiment) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *AppStoreVersionExperiment) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *AppStoreVersionExperiment) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *AppStoreVersionExperiment) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *AppStoreVersionExperiment) GetAttributes() AppStoreVersionExperimentAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *AppStoreVersionExperiment) GetAttributesOk() (*AppStoreVersionExperimentAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *AppStoreVersionExperiment) SetAttributes(v AppStoreVersionExperimentAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *AppStoreVersionExperiment) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *AppStoreVersionExperiment) GetRelationships() AppStoreVersionExperimentRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *AppStoreVersionExperiment) GetRelationshipsOk() (*AppStoreVersionExperimentRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *AppStoreVersionExperiment) SetRelationships(v AppStoreVersionExperimentRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *AppStoreVersionExperiment) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *AppStoreVersionExperiment) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppStoreVersionExperiment) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppStoreVersionExperiment) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


