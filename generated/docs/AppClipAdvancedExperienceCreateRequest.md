# AppClipAdvancedExperienceCreateRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**AppClipAdvancedExperienceCreateRequestData**](AppClipAdvancedExperienceCreateRequestData.md) |  | 
**Included** | Pointer to [**[]AppClipAdvancedExperienceLocalizationInlineCreate**](AppClipAdvancedExperienceLocalizationInlineCreate.md) |  | [optional] 

## Methods

### NewAppClipAdvancedExperienceCreateRequest

`func NewAppClipAdvancedExperienceCreateRequest(data AppClipAdvancedExperienceCreateRequestData, ) *AppClipAdvancedExperienceCreateRequest`

NewAppClipAdvancedExperienceCreateRequest instantiates a new AppClipAdvancedExperienceCreateRequest object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppClipAdvancedExperienceCreateRequestWithDefaults

`func NewAppClipAdvancedExperienceCreateRequestWithDefaults() *AppClipAdvancedExperienceCreateRequest`

NewAppClipAdvancedExperienceCreateRequestWithDefaults instantiates a new AppClipAdvancedExperienceCreateRequest object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *AppClipAdvancedExperienceCreateRequest) GetData() AppClipAdvancedExperienceCreateRequestData`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *AppClipAdvancedExperienceCreateRequest) GetDataOk() (*AppClipAdvancedExperienceCreateRequestData, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *AppClipAdvancedExperienceCreateRequest) SetData(v AppClipAdvancedExperienceCreateRequestData)`

SetData sets Data field to given value.


### GetIncluded

`func (o *AppClipAdvancedExperienceCreateRequest) GetIncluded() []AppClipAdvancedExperienceLocalizationInlineCreate`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *AppClipAdvancedExperienceCreateRequest) GetIncludedOk() (*[]AppClipAdvancedExperienceLocalizationInlineCreate, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *AppClipAdvancedExperienceCreateRequest) SetIncluded(v []AppClipAdvancedExperienceLocalizationInlineCreate)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *AppClipAdvancedExperienceCreateRequest) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


