# AppStoreVersionLocalizationsResponseIncludedInner

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**AppPreviewSetAttributes**](AppPreviewSetAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**AppPreviewSetRelationships**](AppPreviewSetRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewAppStoreVersionLocalizationsResponseIncludedInner

`func NewAppStoreVersionLocalizationsResponseIncludedInner(type_ string, id string, links ResourceLinks, ) *AppStoreVersionLocalizationsResponseIncludedInner`

NewAppStoreVersionLocalizationsResponseIncludedInner instantiates a new AppStoreVersionLocalizationsResponseIncludedInner object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppStoreVersionLocalizationsResponseIncludedInnerWithDefaults

`func NewAppStoreVersionLocalizationsResponseIncludedInnerWithDefaults() *AppStoreVersionLocalizationsResponseIncludedInner`

NewAppStoreVersionLocalizationsResponseIncludedInnerWithDefaults instantiates a new AppStoreVersionLocalizationsResponseIncludedInner object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *AppStoreVersionLocalizationsResponseIncludedInner) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *AppStoreVersionLocalizationsResponseIncludedInner) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *AppStoreVersionLocalizationsResponseIncludedInner) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *AppStoreVersionLocalizationsResponseIncludedInner) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *AppStoreVersionLocalizationsResponseIncludedInner) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *AppStoreVersionLocalizationsResponseIncludedInner) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *AppStoreVersionLocalizationsResponseIncludedInner) GetAttributes() AppPreviewSetAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *AppStoreVersionLocalizationsResponseIncludedInner) GetAttributesOk() (*AppPreviewSetAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *AppStoreVersionLocalizationsResponseIncludedInner) SetAttributes(v AppPreviewSetAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *AppStoreVersionLocalizationsResponseIncludedInner) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *AppStoreVersionLocalizationsResponseIncludedInner) GetRelationships() AppPreviewSetRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *AppStoreVersionLocalizationsResponseIncludedInner) GetRelationshipsOk() (*AppPreviewSetRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *AppStoreVersionLocalizationsResponseIncludedInner) SetRelationships(v AppPreviewSetRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *AppStoreVersionLocalizationsResponseIncludedInner) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *AppStoreVersionLocalizationsResponseIncludedInner) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppStoreVersionLocalizationsResponseIncludedInner) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppStoreVersionLocalizationsResponseIncludedInner) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


