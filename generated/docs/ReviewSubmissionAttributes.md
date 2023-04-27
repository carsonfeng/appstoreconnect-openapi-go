# ReviewSubmissionAttributes

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Platform** | Pointer to [**Platform**](Platform.md) |  | [optional] 
**SubmittedDate** | Pointer to **time.Time** |  | [optional] 
**State** | Pointer to **string** |  | [optional] 

## Methods

### NewReviewSubmissionAttributes

`func NewReviewSubmissionAttributes() *ReviewSubmissionAttributes`

NewReviewSubmissionAttributes instantiates a new ReviewSubmissionAttributes object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewReviewSubmissionAttributesWithDefaults

`func NewReviewSubmissionAttributesWithDefaults() *ReviewSubmissionAttributes`

NewReviewSubmissionAttributesWithDefaults instantiates a new ReviewSubmissionAttributes object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetPlatform

`func (o *ReviewSubmissionAttributes) GetPlatform() Platform`

GetPlatform returns the Platform field if non-nil, zero value otherwise.

### GetPlatformOk

`func (o *ReviewSubmissionAttributes) GetPlatformOk() (*Platform, bool)`

GetPlatformOk returns a tuple with the Platform field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPlatform

`func (o *ReviewSubmissionAttributes) SetPlatform(v Platform)`

SetPlatform sets Platform field to given value.

### HasPlatform

`func (o *ReviewSubmissionAttributes) HasPlatform() bool`

HasPlatform returns a boolean if a field has been set.

### GetSubmittedDate

`func (o *ReviewSubmissionAttributes) GetSubmittedDate() time.Time`

GetSubmittedDate returns the SubmittedDate field if non-nil, zero value otherwise.

### GetSubmittedDateOk

`func (o *ReviewSubmissionAttributes) GetSubmittedDateOk() (*time.Time, bool)`

GetSubmittedDateOk returns a tuple with the SubmittedDate field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSubmittedDate

`func (o *ReviewSubmissionAttributes) SetSubmittedDate(v time.Time)`

SetSubmittedDate sets SubmittedDate field to given value.

### HasSubmittedDate

`func (o *ReviewSubmissionAttributes) HasSubmittedDate() bool`

HasSubmittedDate returns a boolean if a field has been set.

### GetState

`func (o *ReviewSubmissionAttributes) GetState() string`

GetState returns the State field if non-nil, zero value otherwise.

### GetStateOk

`func (o *ReviewSubmissionAttributes) GetStateOk() (*string, bool)`

GetStateOk returns a tuple with the State field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetState

`func (o *ReviewSubmissionAttributes) SetState(v string)`

SetState sets State field to given value.

### HasState

`func (o *ReviewSubmissionAttributes) HasState() bool`

HasState returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


