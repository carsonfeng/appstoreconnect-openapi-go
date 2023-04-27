# ReviewSubmissionsResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**[]ReviewSubmission**](ReviewSubmission.md) |  | 
**Included** | Pointer to [**[]ReviewSubmissionsResponseIncludedInner**](ReviewSubmissionsResponseIncludedInner.md) |  | [optional] 
**Links** | [**PagedDocumentLinks**](PagedDocumentLinks.md) |  | 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 

## Methods

### NewReviewSubmissionsResponse

`func NewReviewSubmissionsResponse(data []ReviewSubmission, links PagedDocumentLinks, ) *ReviewSubmissionsResponse`

NewReviewSubmissionsResponse instantiates a new ReviewSubmissionsResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewReviewSubmissionsResponseWithDefaults

`func NewReviewSubmissionsResponseWithDefaults() *ReviewSubmissionsResponse`

NewReviewSubmissionsResponseWithDefaults instantiates a new ReviewSubmissionsResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *ReviewSubmissionsResponse) GetData() []ReviewSubmission`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *ReviewSubmissionsResponse) GetDataOk() (*[]ReviewSubmission, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *ReviewSubmissionsResponse) SetData(v []ReviewSubmission)`

SetData sets Data field to given value.


### GetIncluded

`func (o *ReviewSubmissionsResponse) GetIncluded() []ReviewSubmissionsResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *ReviewSubmissionsResponse) GetIncludedOk() (*[]ReviewSubmissionsResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *ReviewSubmissionsResponse) SetIncluded(v []ReviewSubmissionsResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *ReviewSubmissionsResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *ReviewSubmissionsResponse) GetLinks() PagedDocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *ReviewSubmissionsResponse) GetLinksOk() (*PagedDocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *ReviewSubmissionsResponse) SetLinks(v PagedDocumentLinks)`

SetLinks sets Links field to given value.


### GetMeta

`func (o *ReviewSubmissionsResponse) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *ReviewSubmissionsResponse) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *ReviewSubmissionsResponse) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *ReviewSubmissionsResponse) HasMeta() bool`

HasMeta returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


