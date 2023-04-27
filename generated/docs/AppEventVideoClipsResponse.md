# AppEventVideoClipsResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**[]AppEventVideoClip**](AppEventVideoClip.md) |  | 
**Included** | Pointer to [**[]AppEventLocalization**](AppEventLocalization.md) |  | [optional] 
**Links** | [**PagedDocumentLinks**](PagedDocumentLinks.md) |  | 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 

## Methods

### NewAppEventVideoClipsResponse

`func NewAppEventVideoClipsResponse(data []AppEventVideoClip, links PagedDocumentLinks, ) *AppEventVideoClipsResponse`

NewAppEventVideoClipsResponse instantiates a new AppEventVideoClipsResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppEventVideoClipsResponseWithDefaults

`func NewAppEventVideoClipsResponseWithDefaults() *AppEventVideoClipsResponse`

NewAppEventVideoClipsResponseWithDefaults instantiates a new AppEventVideoClipsResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *AppEventVideoClipsResponse) GetData() []AppEventVideoClip`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *AppEventVideoClipsResponse) GetDataOk() (*[]AppEventVideoClip, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *AppEventVideoClipsResponse) SetData(v []AppEventVideoClip)`

SetData sets Data field to given value.


### GetIncluded

`func (o *AppEventVideoClipsResponse) GetIncluded() []AppEventLocalization`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *AppEventVideoClipsResponse) GetIncludedOk() (*[]AppEventLocalization, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *AppEventVideoClipsResponse) SetIncluded(v []AppEventLocalization)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *AppEventVideoClipsResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *AppEventVideoClipsResponse) GetLinks() PagedDocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppEventVideoClipsResponse) GetLinksOk() (*PagedDocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppEventVideoClipsResponse) SetLinks(v PagedDocumentLinks)`

SetLinks sets Links field to given value.


### GetMeta

`func (o *AppEventVideoClipsResponse) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *AppEventVideoClipsResponse) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *AppEventVideoClipsResponse) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *AppEventVideoClipsResponse) HasMeta() bool`

HasMeta returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


