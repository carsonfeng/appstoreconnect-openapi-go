# CustomerReviewResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**CustomerReview**](CustomerReview.md) |  | 
**Included** | Pointer to [**[]CustomerReviewResponseV1**](CustomerReviewResponseV1.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewCustomerReviewResponse

`func NewCustomerReviewResponse(data CustomerReview, links DocumentLinks, ) *CustomerReviewResponse`

NewCustomerReviewResponse instantiates a new CustomerReviewResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCustomerReviewResponseWithDefaults

`func NewCustomerReviewResponseWithDefaults() *CustomerReviewResponse`

NewCustomerReviewResponseWithDefaults instantiates a new CustomerReviewResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *CustomerReviewResponse) GetData() CustomerReview`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *CustomerReviewResponse) GetDataOk() (*CustomerReview, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *CustomerReviewResponse) SetData(v CustomerReview)`

SetData sets Data field to given value.


### GetIncluded

`func (o *CustomerReviewResponse) GetIncluded() []CustomerReviewResponseV1`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *CustomerReviewResponse) GetIncludedOk() (*[]CustomerReviewResponseV1, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *CustomerReviewResponse) SetIncluded(v []CustomerReviewResponseV1)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *CustomerReviewResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *CustomerReviewResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *CustomerReviewResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *CustomerReviewResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


