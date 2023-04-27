# AppClipAdvancedExperienceResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**AppClipAdvancedExperience**](AppClipAdvancedExperience.md) |  | 
**Included** | Pointer to [**[]AppClipAdvancedExperiencesResponseIncludedInner**](AppClipAdvancedExperiencesResponseIncludedInner.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewAppClipAdvancedExperienceResponse

`func NewAppClipAdvancedExperienceResponse(data AppClipAdvancedExperience, links DocumentLinks, ) *AppClipAdvancedExperienceResponse`

NewAppClipAdvancedExperienceResponse instantiates a new AppClipAdvancedExperienceResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppClipAdvancedExperienceResponseWithDefaults

`func NewAppClipAdvancedExperienceResponseWithDefaults() *AppClipAdvancedExperienceResponse`

NewAppClipAdvancedExperienceResponseWithDefaults instantiates a new AppClipAdvancedExperienceResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *AppClipAdvancedExperienceResponse) GetData() AppClipAdvancedExperience`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *AppClipAdvancedExperienceResponse) GetDataOk() (*AppClipAdvancedExperience, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *AppClipAdvancedExperienceResponse) SetData(v AppClipAdvancedExperience)`

SetData sets Data field to given value.


### GetIncluded

`func (o *AppClipAdvancedExperienceResponse) GetIncluded() []AppClipAdvancedExperiencesResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *AppClipAdvancedExperienceResponse) GetIncludedOk() (*[]AppClipAdvancedExperiencesResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *AppClipAdvancedExperienceResponse) SetIncluded(v []AppClipAdvancedExperiencesResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *AppClipAdvancedExperienceResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *AppClipAdvancedExperienceResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppClipAdvancedExperienceResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppClipAdvancedExperienceResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


