# ReviewSubmissionRelationshipsItems

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Links** | Pointer to [**AppAvailabilityRelationshipsAppLinks**](AppAvailabilityRelationshipsAppLinks.md) |  | [optional] 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 
**Data** | Pointer to [**[]ReviewSubmissionRelationshipsItemsDataInner**](ReviewSubmissionRelationshipsItemsDataInner.md) |  | [optional] 

## Methods

### NewReviewSubmissionRelationshipsItems

`func NewReviewSubmissionRelationshipsItems() *ReviewSubmissionRelationshipsItems`

NewReviewSubmissionRelationshipsItems instantiates a new ReviewSubmissionRelationshipsItems object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewReviewSubmissionRelationshipsItemsWithDefaults

`func NewReviewSubmissionRelationshipsItemsWithDefaults() *ReviewSubmissionRelationshipsItems`

NewReviewSubmissionRelationshipsItemsWithDefaults instantiates a new ReviewSubmissionRelationshipsItems object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetLinks

`func (o *ReviewSubmissionRelationshipsItems) GetLinks() AppAvailabilityRelationshipsAppLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *ReviewSubmissionRelationshipsItems) GetLinksOk() (*AppAvailabilityRelationshipsAppLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *ReviewSubmissionRelationshipsItems) SetLinks(v AppAvailabilityRelationshipsAppLinks)`

SetLinks sets Links field to given value.

### HasLinks

`func (o *ReviewSubmissionRelationshipsItems) HasLinks() bool`

HasLinks returns a boolean if a field has been set.

### GetMeta

`func (o *ReviewSubmissionRelationshipsItems) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *ReviewSubmissionRelationshipsItems) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *ReviewSubmissionRelationshipsItems) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *ReviewSubmissionRelationshipsItems) HasMeta() bool`

HasMeta returns a boolean if a field has been set.

### GetData

`func (o *ReviewSubmissionRelationshipsItems) GetData() []ReviewSubmissionRelationshipsItemsDataInner`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *ReviewSubmissionRelationshipsItems) GetDataOk() (*[]ReviewSubmissionRelationshipsItemsDataInner, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *ReviewSubmissionRelationshipsItems) SetData(v []ReviewSubmissionRelationshipsItemsDataInner)`

SetData sets Data field to given value.

### HasData

`func (o *ReviewSubmissionRelationshipsItems) HasData() bool`

HasData returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


