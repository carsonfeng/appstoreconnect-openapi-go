# AppEventVideoClipResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**AppEventVideoClip**](AppEventVideoClip.md) |  | 
**Included** | Pointer to [**[]AppEventLocalization**](AppEventLocalization.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewAppEventVideoClipResponse

`func NewAppEventVideoClipResponse(data AppEventVideoClip, links DocumentLinks, ) *AppEventVideoClipResponse`

NewAppEventVideoClipResponse instantiates a new AppEventVideoClipResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppEventVideoClipResponseWithDefaults

`func NewAppEventVideoClipResponseWithDefaults() *AppEventVideoClipResponse`

NewAppEventVideoClipResponseWithDefaults instantiates a new AppEventVideoClipResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *AppEventVideoClipResponse) GetData() AppEventVideoClip`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *AppEventVideoClipResponse) GetDataOk() (*AppEventVideoClip, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *AppEventVideoClipResponse) SetData(v AppEventVideoClip)`

SetData sets Data field to given value.


### GetIncluded

`func (o *AppEventVideoClipResponse) GetIncluded() []AppEventLocalization`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *AppEventVideoClipResponse) GetIncludedOk() (*[]AppEventLocalization, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *AppEventVideoClipResponse) SetIncluded(v []AppEventLocalization)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *AppEventVideoClipResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *AppEventVideoClipResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppEventVideoClipResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppEventVideoClipResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


