# AppEventScreenshotResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**AppEventScreenshot**](AppEventScreenshot.md) |  | 
**Included** | Pointer to [**[]AppEventLocalization**](AppEventLocalization.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewAppEventScreenshotResponse

`func NewAppEventScreenshotResponse(data AppEventScreenshot, links DocumentLinks, ) *AppEventScreenshotResponse`

NewAppEventScreenshotResponse instantiates a new AppEventScreenshotResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppEventScreenshotResponseWithDefaults

`func NewAppEventScreenshotResponseWithDefaults() *AppEventScreenshotResponse`

NewAppEventScreenshotResponseWithDefaults instantiates a new AppEventScreenshotResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *AppEventScreenshotResponse) GetData() AppEventScreenshot`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *AppEventScreenshotResponse) GetDataOk() (*AppEventScreenshot, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *AppEventScreenshotResponse) SetData(v AppEventScreenshot)`

SetData sets Data field to given value.


### GetIncluded

`func (o *AppEventScreenshotResponse) GetIncluded() []AppEventLocalization`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *AppEventScreenshotResponse) GetIncludedOk() (*[]AppEventLocalization, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *AppEventScreenshotResponse) SetIncluded(v []AppEventLocalization)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *AppEventScreenshotResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *AppEventScreenshotResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppEventScreenshotResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppEventScreenshotResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


