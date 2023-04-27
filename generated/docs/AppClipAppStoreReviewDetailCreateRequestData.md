# AppClipAppStoreReviewDetailCreateRequestData

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Type** | **string** |  | 
**Attributes** | Pointer to [**AppClipAppStoreReviewDetailAttributes**](AppClipAppStoreReviewDetailAttributes.md) |  | [optional] 
**Relationships** | [**AppClipAppStoreReviewDetailCreateRequestDataRelationships**](AppClipAppStoreReviewDetailCreateRequestDataRelationships.md) |  | 

## Methods

### NewAppClipAppStoreReviewDetailCreateRequestData

`func NewAppClipAppStoreReviewDetailCreateRequestData(type_ string, relationships AppClipAppStoreReviewDetailCreateRequestDataRelationships, ) *AppClipAppStoreReviewDetailCreateRequestData`

NewAppClipAppStoreReviewDetailCreateRequestData instantiates a new AppClipAppStoreReviewDetailCreateRequestData object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppClipAppStoreReviewDetailCreateRequestDataWithDefaults

`func NewAppClipAppStoreReviewDetailCreateRequestDataWithDefaults() *AppClipAppStoreReviewDetailCreateRequestData`

NewAppClipAppStoreReviewDetailCreateRequestDataWithDefaults instantiates a new AppClipAppStoreReviewDetailCreateRequestData object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetType

`func (o *AppClipAppStoreReviewDetailCreateRequestData) GetType() string`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *AppClipAppStoreReviewDetailCreateRequestData) GetTypeOk() (*string, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *AppClipAppStoreReviewDetailCreateRequestData) SetType(v string)`

SetType sets Type field to given value.


### GetAttributes

`func (o *AppClipAppStoreReviewDetailCreateRequestData) GetAttributes() AppClipAppStoreReviewDetailAttributes`

GetAttributes returns the Attributes field if non-nil, zero value otherwise.

### GetAttributesOk

`func (o *AppClipAppStoreReviewDetailCreateRequestData) GetAttributesOk() (*AppClipAppStoreReviewDetailAttributes, bool)`

GetAttributesOk returns a tuple with the Attributes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAttributes

`func (o *AppClipAppStoreReviewDetailCreateRequestData) SetAttributes(v AppClipAppStoreReviewDetailAttributes)`

SetAttributes sets Attributes field to given value.

### HasAttributes

`func (o *AppClipAppStoreReviewDetailCreateRequestData) HasAttributes() bool`

HasAttributes returns a boolean if a field has been set.

### GetRelationships

`func (o *AppClipAppStoreReviewDetailCreateRequestData) GetRelationships() AppClipAppStoreReviewDetailCreateRequestDataRelationships`

GetRelationships returns the Relationships field if non-nil, zero value otherwise.

### GetRelationshipsOk

`func (o *AppClipAppStoreReviewDetailCreateRequestData) GetRelationshipsOk() (*AppClipAppStoreReviewDetailCreateRequestDataRelationships, bool)`

GetRelationshipsOk returns a tuple with the Relationships field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRelationships

`func (o *AppClipAppStoreReviewDetailCreateRequestData) SetRelationships(v AppClipAppStoreReviewDetailCreateRequestDataRelationships)`

SetRelationships sets Relationships field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


