# AppScreenshotSetsResponseIncludedInner

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**AppScreenshotAttributes**](AppScreenshotAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**AppScreenshotRelationships**](AppScreenshotRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewAppScreenshotSetsResponseIncludedInner

`func NewAppScreenshotSetsResponseIncludedInner(type_ string, id string, links ResourceLinks, ) *AppScreenshotSetsResponseIncludedInner`

NewAppScreenshotSetsResponseIncludedInner instantiates a new AppScreenshotSetsResponseIncludedInner object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppScreenshotSetsResponseIncludedInnerWithDefaults

`func NewAppScreenshotSetsResponseIncludedInnerWithDefaults() *AppScreenshotSetsResponseIncludedInner`

NewAppScreenshotSetsResponseIncludedInnerWithDefaults instantiates a new AppScreenshotSetsResponseIncludedInner object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *AppScreenshotSetsResponseIncludedInner) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *AppScreenshotSetsResponseIncludedInner) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *AppScreenshotSetsResponseIncludedInner) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *AppScreenshotSetsResponseIncludedInner) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *AppScreenshotSetsResponseIncludedInner) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *AppScreenshotSetsResponseIncludedInner) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *AppScreenshotSetsResponseIncludedInner) GetAttributes() AppScreenshotAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *AppScreenshotSetsResponseIncludedInner) GetAttributesOk() (*AppScreenshotAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *AppScreenshotSetsResponseIncludedInner) SetAttributes(v AppScreenshotAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *AppScreenshotSetsResponseIncludedInner) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *AppScreenshotSetsResponseIncludedInner) GetRelationships() AppScreenshotRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *AppScreenshotSetsResponseIncludedInner) GetRelationshipsOk() (*AppScreenshotRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *AppScreenshotSetsResponseIncludedInner) SetRelationships(v AppScreenshotRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *AppScreenshotSetsResponseIncludedInner) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *AppScreenshotSetsResponseIncludedInner) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppScreenshotSetsResponseIncludedInner) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppScreenshotSetsResponseIncludedInner) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


