# AppClipDefaultExperienceResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**AppClipDefaultExperience**](AppClipDefaultExperience.md) |  | 
**Included** | Pointer to [**[]AppClipDefaultExperiencesResponseIncludedInner**](AppClipDefaultExperiencesResponseIncludedInner.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewAppClipDefaultExperienceResponse

`func NewAppClipDefaultExperienceResponse(data AppClipDefaultExperience, links DocumentLinks, ) *AppClipDefaultExperienceResponse`

NewAppClipDefaultExperienceResponse instantiates a new AppClipDefaultExperienceResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppClipDefaultExperienceResponseWithDefaults

`func NewAppClipDefaultExperienceResponseWithDefaults() *AppClipDefaultExperienceResponse`

NewAppClipDefaultExperienceResponseWithDefaults instantiates a new AppClipDefaultExperienceResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *AppClipDefaultExperienceResponse) GetData() AppClipDefaultExperience`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *AppClipDefaultExperienceResponse) GetDataOk() (*AppClipDefaultExperience, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *AppClipDefaultExperienceResponse) SetData(v AppClipDefaultExperience)`

SetData sets Data field to given value.


### GetIncluded

`func (o *AppClipDefaultExperienceResponse) GetIncluded() []AppClipDefaultExperiencesResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *AppClipDefaultExperienceResponse) GetIncludedOk() (*[]AppClipDefaultExperiencesResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *AppClipDefaultExperienceResponse) SetIncluded(v []AppClipDefaultExperiencesResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *AppClipDefaultExperienceResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *AppClipDefaultExperienceResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppClipDefaultExperienceResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppClipDefaultExperienceResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


