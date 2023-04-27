# ReviewSubmissionItemResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**ReviewSubmissionItem**](ReviewSubmissionItem.md) |  | 
**Included** | Pointer to [**[]ReviewSubmissionItemsResponseIncludedInner**](ReviewSubmissionItemsResponseIncludedInner.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewReviewSubmissionItemResponse

`func NewReviewSubmissionItemResponse(data ReviewSubmissionItem, links DocumentLinks, ) *ReviewSubmissionItemResponse`

NewReviewSubmissionItemResponse instantiates a new ReviewSubmissionItemResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewReviewSubmissionItemResponseWithDefaults

`func NewReviewSubmissionItemResponseWithDefaults() *ReviewSubmissionItemResponse`

NewReviewSubmissionItemResponseWithDefaults instantiates a new ReviewSubmissionItemResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *ReviewSubmissionItemResponse) GetData() ReviewSubmissionItem`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *ReviewSubmissionItemResponse) GetDataOk() (*ReviewSubmissionItem, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *ReviewSubmissionItemResponse) SetData(v ReviewSubmissionItem)`

SetData sets Data field to given value.


### GetIncluded

`func (o *ReviewSubmissionItemResponse) GetIncluded() []ReviewSubmissionItemsResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *ReviewSubmissionItemResponse) GetIncludedOk() (*[]ReviewSubmissionItemsResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *ReviewSubmissionItemResponse) SetIncluded(v []ReviewSubmissionItemsResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *ReviewSubmissionItemResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *ReviewSubmissionItemResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *ReviewSubmissionItemResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *ReviewSubmissionItemResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


