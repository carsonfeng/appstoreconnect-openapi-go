# ReviewSubmissionResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**ReviewSubmission**](ReviewSubmission.md) |  | 
**Included** | Pointer to [**[]ReviewSubmissionsResponseIncludedInner**](ReviewSubmissionsResponseIncludedInner.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewReviewSubmissionResponse

`func NewReviewSubmissionResponse(data ReviewSubmission, links DocumentLinks, ) *ReviewSubmissionResponse`

NewReviewSubmissionResponse instantiates a new ReviewSubmissionResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewReviewSubmissionResponseWithDefaults

`func NewReviewSubmissionResponseWithDefaults() *ReviewSubmissionResponse`

NewReviewSubmissionResponseWithDefaults instantiates a new ReviewSubmissionResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *ReviewSubmissionResponse) GetData() ReviewSubmission`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *ReviewSubmissionResponse) GetDataOk() (*ReviewSubmission, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *ReviewSubmissionResponse) SetData(v ReviewSubmission)`

SetData sets Data field to given value.


### GetIncluded

`func (o *ReviewSubmissionResponse) GetIncluded() []ReviewSubmissionsResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *ReviewSubmissionResponse) GetIncludedOk() (*[]ReviewSubmissionsResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *ReviewSubmissionResponse) SetIncluded(v []ReviewSubmissionsResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *ReviewSubmissionResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *ReviewSubmissionResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *ReviewSubmissionResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *ReviewSubmissionResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


