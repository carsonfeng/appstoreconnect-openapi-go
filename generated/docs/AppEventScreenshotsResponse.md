# AppEventScreenshotsResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**[]AppEventScreenshot**](AppEventScreenshot.md) |  | 
**Included** | Pointer to [**[]AppEventLocalization**](AppEventLocalization.md) |  | [optional] 
**Links** | [**PagedDocumentLinks**](PagedDocumentLinks.md) |  | 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 

## Methods

### NewAppEventScreenshotsResponse

`func NewAppEventScreenshotsResponse(data []AppEventScreenshot, links PagedDocumentLinks, ) *AppEventScreenshotsResponse`

NewAppEventScreenshotsResponse instantiates a new AppEventScreenshotsResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppEventScreenshotsResponseWithDefaults

`func NewAppEventScreenshotsResponseWithDefaults() *AppEventScreenshotsResponse`

NewAppEventScreenshotsResponseWithDefaults instantiates a new AppEventScreenshotsResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *AppEventScreenshotsResponse) GetData() []AppEventScreenshot`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *AppEventScreenshotsResponse) GetDataOk() (*[]AppEventScreenshot, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *AppEventScreenshotsResponse) SetData(v []AppEventScreenshot)`

SetData sets Data field to given value.


### GetIncluded

`func (o *AppEventScreenshotsResponse) GetIncluded() []AppEventLocalization`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *AppEventScreenshotsResponse) GetIncludedOk() (*[]AppEventLocalization, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *AppEventScreenshotsResponse) SetIncluded(v []AppEventLocalization)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *AppEventScreenshotsResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *AppEventScreenshotsResponse) GetLinks() PagedDocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppEventScreenshotsResponse) GetLinksOk() (*PagedDocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppEventScreenshotsResponse) SetLinks(v PagedDocumentLinks)`

SetLinks sets Links field to given value.


### GetMeta

`func (o *AppEventScreenshotsResponse) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *AppEventScreenshotsResponse) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *AppEventScreenshotsResponse) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *AppEventScreenshotsResponse) HasMeta() bool`

HasMeta returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


