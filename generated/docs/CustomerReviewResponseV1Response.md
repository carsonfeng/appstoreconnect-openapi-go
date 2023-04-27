# CustomerReviewResponseV1Response

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**CustomerReviewResponseV1**](CustomerReviewResponseV1.md) |  | 
**Included** | Pointer to [**[]CustomerReview**](CustomerReview.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewCustomerReviewResponseV1Response

`func NewCustomerReviewResponseV1Response(data CustomerReviewResponseV1, links DocumentLinks, ) *CustomerReviewResponseV1Response`

NewCustomerReviewResponseV1Response instantiates a new CustomerReviewResponseV1Response object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCustomerReviewResponseV1ResponseWithDefaults

`func NewCustomerReviewResponseV1ResponseWithDefaults() *CustomerReviewResponseV1Response`

NewCustomerReviewResponseV1ResponseWithDefaults instantiates a new CustomerReviewResponseV1Response object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *CustomerReviewResponseV1Response) GetData() CustomerReviewResponseV1`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *CustomerReviewResponseV1Response) GetDataOk() (*CustomerReviewResponseV1, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *CustomerReviewResponseV1Response) SetData(v CustomerReviewResponseV1)`

SetData sets Data field to given value.


### GetIncluded

`func (o *CustomerReviewResponseV1Response) GetIncluded() []CustomerReview`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *CustomerReviewResponseV1Response) GetIncludedOk() (*[]CustomerReview, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *CustomerReviewResponseV1Response) SetIncluded(v []CustomerReview)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *CustomerReviewResponseV1Response) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *CustomerReviewResponseV1Response) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *CustomerReviewResponseV1Response) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *CustomerReviewResponseV1Response) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


