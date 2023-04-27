# AppEventVideoClipCreateRequestData

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Attributes** | [**AppEventVideoClipCreateRequestDataAttributes**](AppEventVideoClipCreateRequestDataAttributes.md) |  | 
**Relationships** | [**AppEventScreenshotCreateRequestDataRelationships**](AppEventScreenshotCreateRequestDataRelationships.md) |  | 

## Methods

### NewAppEventVideoClipCreateRequestData

`func NewAppEventVideoClipCreateRequestData(type_ string, attributes AppEventVideoClipCreateRequestDataAttributes, relationships AppEventScreenshotCreateRequestDataRelationships, ) *AppEventVideoClipCreateRequestData`

NewAppEventVideoClipCreateRequestData instantiates a new AppEventVideoClipCreateRequestData object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppEventVideoClipCreateRequestDataWithDefaults

`func NewAppEventVideoClipCreateRequestDataWithDefaults() *AppEventVideoClipCreateRequestData`

NewAppEventVideoClipCreateRequestDataWithDefaults instantiates a new AppEventVideoClipCreateRequestData object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *AppEventVideoClipCreateRequestData) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *AppEventVideoClipCreateRequestData) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *AppEventVideoClipCreateRequestData) SetType(v string)`

SetType sets Type field to given value.


### GetAttributes

`func (o *AppEventVideoClipCreateRequestData) GetAttributes() AppEventVideoClipCreateRequestDataAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *AppEventVideoClipCreateRequestData) GetAttributesOk() (*AppEventVideoClipCreateRequestDataAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *AppEventVideoClipCreateRequestData) SetAttributes(v AppEventVideoClipCreateRequestDataAttributes)`

SetAttributes sets Attributes field to given value.


### GetRelationships

`func (o *AppEventVideoClipCreateRequestData) GetRelationships() AppEventScreenshotCreateRequestDataRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *AppEventVideoClipCreateRequestData) GetRelationshipsOk() (*AppEventScreenshotCreateRequestDataRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *AppEventVideoClipCreateRequestData) SetRelationships(v AppEventScreenshotCreateRequestDataRelationships)`

SetRelationships sets Relationships field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


