# AppEventScreenshot

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Id** | **string** |  | 
**Attributes** | Pointer to [**AppEventScreenshotAttributes**](AppEventScreenshotAttributes.md) |  | [optional] 
**Relationships** | Pointer to [**AppEventScreenshotRelationships**](AppEventScreenshotRelationships.md) |  | [optional] 
**Links** | [**ResourceLinks**](ResourceLinks.md) |  | 

## Methods

### NewAppEventScreenshot

`func NewAppEventScreenshot(type_ string, id string, links ResourceLinks, ) *AppEventScreenshot`

NewAppEventScreenshot instantiates a new AppEventScreenshot object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppEventScreenshotWithDefaults

`func NewAppEventScreenshotWithDefaults() *AppEventScreenshot`

NewAppEventScreenshotWithDefaults instantiates a new AppEventScreenshot object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *AppEventScreenshot) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *AppEventScreenshot) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *AppEventScreenshot) SetType(v string)`

SetType sets Type field to given value.


### GetId

`func (o *AppEventScreenshot) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *AppEventScreenshot) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *AppEventScreenshot) SetId(v string)`

SetId sets Id field to given value.


### GetAttributes

`func (o *AppEventScreenshot) GetAttributes() AppEventScreenshotAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *AppEventScreenshot) GetAttributesOk() (*AppEventScreenshotAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *AppEventScreenshot) SetAttributes(v AppEventScreenshotAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *AppEventScreenshot) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *AppEventScreenshot) GetRelationships() AppEventScreenshotRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *AppEventScreenshot) GetRelationshipsOk() (*AppEventScreenshotRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *AppEventScreenshot) SetRelationships(v AppEventScreenshotRelationships)`

SetRelationships sets Relationships field to given value.

### HasRelationships

`func (o *AppEventScreenshot) HasRelationships() bool`

HasRelationships returns a boolean if a field has been set.

### GetLinks

`func (o *AppEventScreenshot) GetLinks() ResourceLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppEventScreenshot) GetLinksOk() (*ResourceLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppEventScreenshot) SetLinks(v ResourceLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


