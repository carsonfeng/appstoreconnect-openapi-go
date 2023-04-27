# AppClipResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**AppClip**](AppClip.md) |  | 
**Included** | Pointer to [**[]AppClipsResponseIncludedInner**](AppClipsResponseIncludedInner.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewAppClipResponse

`func NewAppClipResponse(data AppClip, links DocumentLinks, ) *AppClipResponse`

NewAppClipResponse instantiates a new AppClipResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppClipResponseWithDefaults

`func NewAppClipResponseWithDefaults() *AppClipResponse`

NewAppClipResponseWithDefaults instantiates a new AppClipResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *AppClipResponse) GetData() AppClip`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *AppClipResponse) GetDataOk() (*AppClip, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *AppClipResponse) SetData(v AppClip)`

SetData sets Data field to given value.


### GetIncluded

`func (o *AppClipResponse) GetIncluded() []AppClipsResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *AppClipResponse) GetIncludedOk() (*[]AppClipsResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *AppClipResponse) SetIncluded(v []AppClipsResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *AppClipResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *AppClipResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppClipResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppClipResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


