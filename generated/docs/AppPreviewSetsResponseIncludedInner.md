# AppPreviewSetsResponseIncludedInner

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**AppPreviewAttributes**](AppPreviewAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**AppPreviewRelationships**](AppPreviewRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewAppPreviewSetsResponseIncludedInner

`func NewAppPreviewSetsResponseIncludedInner(type_ string, id string, links ResourceLinks, ) *AppPreviewSetsResponseIncludedInner`

NewAppPreviewSetsResponseIncludedInner instantiates a new AppPreviewSetsResponseIncludedInner object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppPreviewSetsResponseIncludedInnerWithDefaults

`func NewAppPreviewSetsResponseIncludedInnerWithDefaults() *AppPreviewSetsResponseIncludedInner`

NewAppPreviewSetsResponseIncludedInnerWithDefaults instantiates a new AppPreviewSetsResponseIncludedInner object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *AppPreviewSetsResponseIncludedInner) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *AppPreviewSetsResponseIncludedInner) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *AppPreviewSetsResponseIncludedInner) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *AppPreviewSetsResponseIncludedInner) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *AppPreviewSetsResponseIncludedInner) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *AppPreviewSetsResponseIncludedInner) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *AppPreviewSetsResponseIncludedInner) GetAttributes() AppPreviewAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *AppPreviewSetsResponseIncludedInner) GetAttributesOk() (*AppPreviewAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *AppPreviewSetsResponseIncludedInner) SetAttributes(v AppPreviewAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *AppPreviewSetsResponseIncludedInner) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *AppPreviewSetsResponseIncludedInner) GetRelationships() AppPreviewRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *AppPreviewSetsResponseIncludedInner) GetRelationshipsOk() (*AppPreviewRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *AppPreviewSetsResponseIncludedInner) SetRelationships(v AppPreviewRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *AppPreviewSetsResponseIncludedInner) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *AppPreviewSetsResponseIncludedInner) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppPreviewSetsResponseIncludedInner) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppPreviewSetsResponseIncludedInner) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


