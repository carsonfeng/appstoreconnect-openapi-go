# ReviewSubmissionItemsResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**[]ReviewSubmissionItem**](ReviewSubmissionItem.md) |  | 
**Included** | Pointer to [**[]ReviewSubmissionItemsResponseIncludedInner**](ReviewSubmissionItemsResponseIncludedInner.md) |  | [optional] 
**Links** | [**PagedDocumentLinks**](PagedDocumentLinks.md) |  | 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 

## Methods

### NewReviewSubmissionItemsResponse

`func NewReviewSubmissionItemsResponse(data []ReviewSubmissionItem, links PagedDocumentLinks, ) *ReviewSubmissionItemsResponse`

NewReviewSubmissionItemsResponse instantiates a new ReviewSubmissionItemsResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewReviewSubmissionItemsResponseWithDefaults

`func NewReviewSubmissionItemsResponseWithDefaults() *ReviewSubmissionItemsResponse`

NewReviewSubmissionItemsResponseWithDefaults instantiates a new ReviewSubmissionItemsResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *ReviewSubmissionItemsResponse) GetData() []ReviewSubmissionItem`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *ReviewSubmissionItemsResponse) GetDataOk() (*[]ReviewSubmissionItem, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *ReviewSubmissionItemsResponse) SetData(v []ReviewSubmissionItem)`

SetData sets Data field to given value.


### GetIncluded

`func (o *ReviewSubmissionItemsResponse) GetIncluded() []ReviewSubmissionItemsResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *ReviewSubmissionItemsResponse) GetIncludedOk() (*[]ReviewSubmissionItemsResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *ReviewSubmissionItemsResponse) SetIncluded(v []ReviewSubmissionItemsResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *ReviewSubmissionItemsResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *ReviewSubmissionItemsResponse) GetLinks() PagedDocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *ReviewSubmissionItemsResponse) GetLinksOk() (*PagedDocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *ReviewSubmissionItemsResponse) SetLinks(v PagedDocumentLinks)`

SetLinks sets Links field to given value.


### GetMeta

`func (o *ReviewSubmissionItemsResponse) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *ReviewSubmissionItemsResponse) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *ReviewSubmissionItemsResponse) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *ReviewSubmissionItemsResponse) HasMeta() bool`

HasMeta returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


