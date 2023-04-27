# SubscriptionGroupSubmissionResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**SubscriptionGroupSubmission**](SubscriptionGroupSubmission.md) |  | 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewSubscriptionGroupSubmissionResponse

`func NewSubscriptionGroupSubmissionResponse(data SubscriptionGroupSubmission, links DocumentLinks, ) *SubscriptionGroupSubmissionResponse`

NewSubscriptionGroupSubmissionResponse instantiates a new SubscriptionGroupSubmissionResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionGroupSubmissionResponseWithDefaults

`func NewSubscriptionGroupSubmissionResponseWithDefaults() *SubscriptionGroupSubmissionResponse`

NewSubscriptionGroupSubmissionResponseWithDefaults instantiates a new SubscriptionGroupSubmissionResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *SubscriptionGroupSubmissionResponse) GetData() SubscriptionGroupSubmission`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *SubscriptionGroupSubmissionResponse) GetDataOk() (*SubscriptionGroupSubmission, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *SubscriptionGroupSubmissionResponse) SetData(v SubscriptionGroupSubmission)`

SetData sets Data field to given value.


### GetLinks

`func (o *SubscriptionGroupSubmissionResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *SubscriptionGroupSubmissionResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *SubscriptionGroupSubmissionResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


