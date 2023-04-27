# AppClipDefaultExperienceLocalizationResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**AppClipDefaultExperienceLocalization**](AppClipDefaultExperienceLocalization.md) |  | 
**Included** | Pointer to [**[]AppClipDefaultExperienceLocalizationsResponseIncludedInner**](AppClipDefaultExperienceLocalizationsResponseIncludedInner.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewAppClipDefaultExperienceLocalizationResponse

`func NewAppClipDefaultExperienceLocalizationResponse(data AppClipDefaultExperienceLocalization, links DocumentLinks, ) *AppClipDefaultExperienceLocalizationResponse`

NewAppClipDefaultExperienceLocalizationResponse instantiates a new AppClipDefaultExperienceLocalizationResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppClipDefaultExperienceLocalizationResponseWithDefaults

`func NewAppClipDefaultExperienceLocalizationResponseWithDefaults() *AppClipDefaultExperienceLocalizationResponse`

NewAppClipDefaultExperienceLocalizationResponseWithDefaults instantiates a new AppClipDefaultExperienceLocalizationResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *AppClipDefaultExperienceLocalizationResponse) GetData() AppClipDefaultExperienceLocalization`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *AppClipDefaultExperienceLocalizationResponse) GetDataOk() (*AppClipDefaultExperienceLocalization, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *AppClipDefaultExperienceLocalizationResponse) SetData(v AppClipDefaultExperienceLocalization)`

SetData sets Data field to given value.


### GetIncluded

`func (o *AppClipDefaultExperienceLocalizationResponse) GetIncluded() []AppClipDefaultExperienceLocalizationsResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *AppClipDefaultExperienceLocalizationResponse) GetIncludedOk() (*[]AppClipDefaultExperienceLocalizationsResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *AppClipDefaultExperienceLocalizationResponse) SetIncluded(v []AppClipDefaultExperienceLocalizationsResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *AppClipDefaultExperienceLocalizationResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *AppClipDefaultExperienceLocalizationResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppClipDefaultExperienceLocalizationResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppClipDefaultExperienceLocalizationResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


