# SubscriptionIntroductoryOfferInlineCreateAttributes

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**StartDate** | Pointer to **string** |  | [optional] 
**EndDate** | Pointer to **string** |  | [optional] 
**Duration** | [**SubscriptionOfferDuration**](SubscriptionOfferDuration.md) |  | 
**OfferMode** | [**SubscriptionOfferMode**](SubscriptionOfferMode.md) |  | 
**NumberOfPeriods** | **int32** |  | 

## Methods

### NewSubscriptionIntroductoryOfferInlineCreateAttributes

`func NewSubscriptionIntroductoryOfferInlineCreateAttributes(duration SubscriptionOfferDuration, offerMode SubscriptionOfferMode, numberOfPeriods int32, ) *SubscriptionIntroductoryOfferInlineCreateAttributes`

NewSubscriptionIntroductoryOfferInlineCreateAttributes instantiates a new SubscriptionIntroductoryOfferInlineCreateAttributes object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionIntroductoryOfferInlineCreateAttributesWithDefaults

`func NewSubscriptionIntroductoryOfferInlineCreateAttributesWithDefaults() *SubscriptionIntroductoryOfferInlineCreateAttributes`

NewSubscriptionIntroductoryOfferInlineCreateAttributesWithDefaults instantiates a new SubscriptionIntroductoryOfferInlineCreateAttributes object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetStartDate

`func (o *SubscriptionIntroductoryOfferInlineCreateAttributes) GetStartDate() string`

GetStartDate returns the StartDate field if non-nil, zero value otherwise.

### GetStartDateOk

`func (o *SubscriptionIntroductoryOfferInlineCreateAttributes) GetStartDateOk() (*string, bool)`

GetStartDateOk returns a tuple with the StartDate field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetStartDate

`func (o *SubscriptionIntroductoryOfferInlineCreateAttributes) SetStartDate(v string)`

SetStartDate sets StartDate field to given value.

### HasStartDate

`func (o *SubscriptionIntroductoryOfferInlineCreateAttributes) HasStartDate() bool`

HasStartDate returns a boolean if a field has been set.

### GetEndDate

`func (o *SubscriptionIntroductoryOfferInlineCreateAttributes) GetEndDate() string`

GetEndDate returns the EndDate field if non-nil, zero value otherwise.

### GetEndDateOk

`func (o *SubscriptionIntroductoryOfferInlineCreateAttributes) GetEndDateOk() (*string, bool)`

GetEndDateOk returns a tuple with the EndDate field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetEndDate

`func (o *SubscriptionIntroductoryOfferInlineCreateAttributes) SetEndDate(v string)`

SetEndDate sets EndDate field to given value.

### HasEndDate

`func (o *SubscriptionIntroductoryOfferInlineCreateAttributes) HasEndDate() bool`

HasEndDate returns a boolean if a field has been set.

### GetDuration

`func (o *SubscriptionIntroductoryOfferInlineCreateAttributes) GetDuration() SubscriptionOfferDuration`

GetDuration returns the Duration field if non-nil, zero value otherwise.

### GetDurationOk

`func (o *SubscriptionIntroductoryOfferInlineCreateAttributes) GetDurationOk() (*SubscriptionOfferDuration, bool)`

GetDurationOk returns a tuple with the Duration field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDuration

`func (o *SubscriptionIntroductoryOfferInlineCreateAttributes) SetDuration(v SubscriptionOfferDuration)`

SetDuration sets Duration field to given value.


### GetOfferMode

`func (o *SubscriptionIntroductoryOfferInlineCreateAttributes) GetOfferMode() SubscriptionOfferMode`

GetOfferMode returns the OfferMode field if non-nil, zero value otherwise.

### GetOfferModeOk

`func (o *SubscriptionIntroductoryOfferInlineCreateAttributes) GetOfferModeOk() (*SubscriptionOfferMode, bool)`

GetOfferModeOk returns a tuple with the OfferMode field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetOfferMode

`func (o *SubscriptionIntroductoryOfferInlineCreateAttributes) SetOfferMode(v SubscriptionOfferMode)`

SetOfferMode sets OfferMode field to given value.


### GetNumberOfPeriods

`func (o *SubscriptionIntroductoryOfferInlineCreateAttributes) GetNumberOfPeriods() int32`

GetNumberOfPeriods returns the NumberOfPeriods field if non-nil, zero value otherwise.

### GetNumberOfPeriodsOk

`func (o *SubscriptionIntroductoryOfferInlineCreateAttributes) GetNumberOfPeriodsOk() (*int32, bool)`

GetNumberOfPeriodsOk returns a tuple with the NumberOfPeriods field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetNumberOfPeriods

`func (o *SubscriptionIntroductoryOfferInlineCreateAttributes) SetNumberOfPeriods(v int32)`

SetNumberOfPeriods sets NumberOfPeriods field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


