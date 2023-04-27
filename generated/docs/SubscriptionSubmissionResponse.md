# SubscriptionSubmissionResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**SubscriptionSubmission**](SubscriptionSubmission.md) |  | 
**Included** | Pointer to [**[]Subscription**](Subscription.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewSubscriptionSubmissionResponse

`func NewSubscriptionSubmissionResponse(data SubscriptionSubmission, links DocumentLinks, ) *SubscriptionSubmissionResponse`

NewSubscriptionSubmissionResponse instantiates a new SubscriptionSubmissionResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionSubmissionResponseWithDefaults

`func NewSubscriptionSubmissionResponseWithDefaults() *SubscriptionSubmissionResponse`

NewSubscriptionSubmissionResponseWithDefaults instantiates a new SubscriptionSubmissionResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *SubscriptionSubmissionResponse) GetData() SubscriptionSubmission`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *SubscriptionSubmissionResponse) GetDataOk() (*SubscriptionSubmission, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *SubscriptionSubmissionResponse) SetData(v SubscriptionSubmission)`

SetData sets Data field to given value.


### GetIncluded

`func (o *SubscriptionSubmissionResponse) GetIncluded() []Subscription`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *SubscriptionSubmissionResponse) GetIncludedOk() (*[]Subscription, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *SubscriptionSubmissionResponse) SetIncluded(v []Subscription)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *SubscriptionSubmissionResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *SubscriptionSubmissionResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *SubscriptionSubmissionResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *SubscriptionSubmissionResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


