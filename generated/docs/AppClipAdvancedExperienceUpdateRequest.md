# AppClipAdvancedExperienceUpdateRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**AppClipAdvancedExperienceUpdateRequestData**](AppClipAdvancedExperienceUpdateRequestData.md) |  | 
**Included** | Pointer to [**[]AppClipAdvancedExperienceLocalizationInlineCreate**](AppClipAdvancedExperienceLocalizationInlineCreate.md) |  | [optional] 

## Methods

### NewAppClipAdvancedExperienceUpdateRequest

`func NewAppClipAdvancedExperienceUpdateRequest(data AppClipAdvancedExperienceUpdateRequestData, ) *AppClipAdvancedExperienceUpdateRequest`

NewAppClipAdvancedExperienceUpdateRequest instantiates a new AppClipAdvancedExperienceUpdateRequest object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppClipAdvancedExperienceUpdateRequestWithDefaults

`func NewAppClipAdvancedExperienceUpdateRequestWithDefaults() *AppClipAdvancedExperienceUpdateRequest`

NewAppClipAdvancedExperienceUpdateRequestWithDefaults instantiates a new AppClipAdvancedExperienceUpdateRequest object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *AppClipAdvancedExperienceUpdateRequest) GetData() AppClipAdvancedExperienceUpdateRequestData`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *AppClipAdvancedExperienceUpdateRequest) GetDataOk() (*AppClipAdvancedExperienceUpdateRequestData, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *AppClipAdvancedExperienceUpdateRequest) SetData(v AppClipAdvancedExperienceUpdateRequestData)`

SetData sets Data field to given value.


### GetIncluded

`func (o *AppClipAdvancedExperienceUpdateRequest) GetIncluded() []AppClipAdvancedExperienceLocalizationInlineCreate`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *AppClipAdvancedExperienceUpdateRequest) GetIncludedOk() (*[]AppClipAdvancedExperienceLocalizationInlineCreate, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *AppClipAdvancedExperienceUpdateRequest) SetIncluded(v []AppClipAdvancedExperienceLocalizationInlineCreate)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *AppClipAdvancedExperienceUpdateRequest) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


