# AppClipHeaderImageResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**AppClipHeaderImage**](AppClipHeaderImage.md) |  | 
**Included** | Pointer to [**[]AppClipDefaultExperienceLocalization**](AppClipDefaultExperienceLocalization.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewAppClipHeaderImageResponse

`func NewAppClipHeaderImageResponse(data AppClipHeaderImage, links DocumentLinks, ) *AppClipHeaderImageResponse`

NewAppClipHeaderImageResponse instantiates a new AppClipHeaderImageResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppClipHeaderImageResponseWithDefaults

`func NewAppClipHeaderImageResponseWithDefaults() *AppClipHeaderImageResponse`

NewAppClipHeaderImageResponseWithDefaults instantiates a new AppClipHeaderImageResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *AppClipHeaderImageResponse) GetData() AppClipHeaderImage`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *AppClipHeaderImageResponse) GetDataOk() (*AppClipHeaderImage, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *AppClipHeaderImageResponse) SetData(v AppClipHeaderImage)`

SetData sets Data field to given value.


### GetIncluded

`func (o *AppClipHeaderImageResponse) GetIncluded() []AppClipDefaultExperienceLocalization`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *AppClipHeaderImageResponse) GetIncludedOk() (*[]AppClipDefaultExperienceLocalization, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *AppClipHeaderImageResponse) SetIncluded(v []AppClipDefaultExperienceLocalization)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *AppClipHeaderImageResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *AppClipHeaderImageResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppClipHeaderImageResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppClipHeaderImageResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


