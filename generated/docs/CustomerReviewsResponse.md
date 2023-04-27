# CustomerReviewsResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**[]CustomerReview**](CustomerReview.md) |  | 
**Included** | Pointer to [**[]CustomerReviewResponseV1**](CustomerReviewResponseV1.md) |  | [optional] 
**Links** | [**PagedDocumentLinks**](PagedDocumentLinks.md) |  | 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 

## Methods

### NewCustomerReviewsResponse

`func NewCustomerReviewsResponse(data []CustomerReview, links PagedDocumentLinks, ) *CustomerReviewsResponse`

NewCustomerReviewsResponse instantiates a new CustomerReviewsResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCustomerReviewsResponseWithDefaults

`func NewCustomerReviewsResponseWithDefaults() *CustomerReviewsResponse`

NewCustomerReviewsResponseWithDefaults instantiates a new CustomerReviewsResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *CustomerReviewsResponse) GetData() []CustomerReview`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *CustomerReviewsResponse) GetDataOk() (*[]CustomerReview, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *CustomerReviewsResponse) SetData(v []CustomerReview)`

SetData sets Data field to given value.


### GetIncluded

`func (o *CustomerReviewsResponse) GetIncluded() []CustomerReviewResponseV1`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *CustomerReviewsResponse) GetIncludedOk() (*[]CustomerReviewResponseV1, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *CustomerReviewsResponse) SetIncluded(v []CustomerReviewResponseV1)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *CustomerReviewsResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *CustomerReviewsResponse) GetLinks() PagedDocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *CustomerReviewsResponse) GetLinksOk() (*PagedDocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *CustomerReviewsResponse) SetLinks(v PagedDocumentLinks)`

SetLinks sets Links field to given value.


### GetMeta

`func (o *CustomerReviewsResponse) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *CustomerReviewsResponse) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *CustomerReviewsResponse) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *CustomerReviewsResponse) HasMeta() bool`

HasMeta returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


