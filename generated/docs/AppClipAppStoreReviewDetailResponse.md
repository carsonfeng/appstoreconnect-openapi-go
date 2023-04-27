# AppClipAppStoreReviewDetailResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**AppClipAppStoreReviewDetail**](AppClipAppStoreReviewDetail.md) |  | 
**Included** | Pointer to [**[]AppClipDefaultExperience**](AppClipDefaultExperience.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewAppClipAppStoreReviewDetailResponse

`func NewAppClipAppStoreReviewDetailResponse(data AppClipAppStoreReviewDetail, links DocumentLinks, ) *AppClipAppStoreReviewDetailResponse`

NewAppClipAppStoreReviewDetailResponse instantiates a new AppClipAppStoreReviewDetailResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppClipAppStoreReviewDetailResponseWithDefaults

`func NewAppClipAppStoreReviewDetailResponseWithDefaults() *AppClipAppStoreReviewDetailResponse`

NewAppClipAppStoreReviewDetailResponseWithDefaults instantiates a new AppClipAppStoreReviewDetailResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *AppClipAppStoreReviewDetailResponse) GetData() AppClipAppStoreReviewDetail`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *AppClipAppStoreReviewDetailResponse) GetDataOk() (*AppClipAppStoreReviewDetail, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *AppClipAppStoreReviewDetailResponse) SetData(v AppClipAppStoreReviewDetail)`

SetData sets Data field to given value.


### GetIncluded

`func (o *AppClipAppStoreReviewDetailResponse) GetIncluded() []AppClipDefaultExperience`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *AppClipAppStoreReviewDetailResponse) GetIncludedOk() (*[]AppClipDefaultExperience, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *AppClipAppStoreReviewDetailResponse) SetIncluded(v []AppClipDefaultExperience)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *AppClipAppStoreReviewDetailResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *AppClipAppStoreReviewDetailResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppClipAppStoreReviewDetailResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppClipAppStoreReviewDetailResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


