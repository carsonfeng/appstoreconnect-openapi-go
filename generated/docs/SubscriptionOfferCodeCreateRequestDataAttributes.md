# SubscriptionOfferCodeCreateRequestDataAttributes

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Name** | **string** |  | 
**CustomerEligibilities** | [**[]SubscriptionCustomerEligibility**](SubscriptionCustomerEligibility.md) |  | 
**OfferEligibility** | [**SubscriptionOfferEligibility**](SubscriptionOfferEligibility.md) |  | 
**Duration** | [**SubscriptionOfferDuration**](SubscriptionOfferDuration.md) |  | 
**OfferMode** | [**SubscriptionOfferMode**](SubscriptionOfferMode.md) |  | 
**NumberOfPeriods** | **int32** |  | 

## Methods

### NewSubscriptionOfferCodeCreateRequestDataAttributes

`func NewSubscriptionOfferCodeCreateRequestDataAttributes(name string, customerEligibilities []SubscriptionCustomerEligibility, offerEligibility SubscriptionOfferEligibility, duration SubscriptionOfferDuration, offerMode SubscriptionOfferMode, numberOfPeriods int32, ) *SubscriptionOfferCodeCreateRequestDataAttributes`

NewSubscriptionOfferCodeCreateRequestDataAttributes instantiates a new SubscriptionOfferCodeCreateRequestDataAttributes object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionOfferCodeCreateRequestDataAttributesWithDefaults

`func NewSubscriptionOfferCodeCreateRequestDataAttributesWithDefaults() *SubscriptionOfferCodeCreateRequestDataAttributes`

NewSubscriptionOfferCodeCreateRequestDataAttributesWithDefaults instantiates a new SubscriptionOfferCodeCreateRequestDataAttributes object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetName

`func (o *SubscriptionOfferCodeCreateRequestDataAttributes) GetName() string`

GetName returns the Name field if non-nil, zero value otherwise.

### GetNameOk

`func (o *SubscriptionOfferCodeCreateRequestDataAttributes) GetNameOk() (*string, bool)`

GetNameOk returns a tuple with the Name field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetName

`func (o *SubscriptionOfferCodeCreateRequestDataAttributes) SetName(v string)`

SetName sets Name field to given value.


### GetCustomerEligibilities

`func (o *SubscriptionOfferCodeCreateRequestDataAttributes) GetCustomerEligibilities() []SubscriptionCustomerEligibility`

GetCustomerEligibilities returns the CustomerEligibilities field if non-nil, zero value otherwise.

### GetCustomerEligibilitiesOk

`func (o *SubscriptionOfferCodeCreateRequestDataAttributes) GetCustomerEligibilitiesOk() (*[]SubscriptionCustomerEligibility, bool)`

GetCustomerEligibilitiesOk returns a tuple with the CustomerEligibilities field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCustomerEligibilities

`func (o *SubscriptionOfferCodeCreateRequestDataAttributes) SetCustomerEligibilities(v []SubscriptionCustomerEligibility)`

SetCustomerEligibilities sets CustomerEligibilities field to given value.


### GetOfferEligibility

`func (o *SubscriptionOfferCodeCreateRequestDataAttributes) GetOfferEligibility() SubscriptionOfferEligibility`

GetOfferEligibility returns the OfferEligibility field if non-nil, zero value otherwise.

### GetOfferEligibilityOk

`func (o *SubscriptionOfferCodeCreateRequestDataAttributes) GetOfferEligibilityOk() (*SubscriptionOfferEligibility, bool)`

GetOfferEligibilityOk returns a tuple with the OfferEligibility field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetOfferEligibility

`func (o *SubscriptionOfferCodeCreateRequestDataAttributes) SetOfferEligibility(v SubscriptionOfferEligibility)`

SetOfferEligibility sets OfferEligibility field to given value.


### GetDuration

`func (o *SubscriptionOfferCodeCreateRequestDataAttributes) GetDuration() SubscriptionOfferDuration`

GetDuration returns the Duration field if non-nil, zero value otherwise.

### GetDurationOk

`func (o *SubscriptionOfferCodeCreateRequestDataAttributes) GetDurationOk() (*SubscriptionOfferDuration, bool)`

GetDurationOk returns a tuple with the Duration field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDuration

`func (o *SubscriptionOfferCodeCreateRequestDataAttributes) SetDuration(v SubscriptionOfferDuration)`

SetDuration sets Duration field to given value.


### GetOfferMode

`func (o *SubscriptionOfferCodeCreateRequestDataAttributes) GetOfferMode() SubscriptionOfferMode`

GetOfferMode returns the OfferMode field if non-nil, zero value otherwise.

### GetOfferModeOk

`func (o *SubscriptionOfferCodeCreateRequestDataAttributes) GetOfferModeOk() (*SubscriptionOfferMode, bool)`

GetOfferModeOk returns a tuple with the OfferMode field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetOfferMode

`func (o *SubscriptionOfferCodeCreateRequestDataAttributes) SetOfferMode(v SubscriptionOfferMode)`

SetOfferMode sets OfferMode field to given value.


### GetNumberOfPeriods

`func (o *SubscriptionOfferCodeCreateRequestDataAttributes) GetNumberOfPeriods() int32`

GetNumberOfPeriods returns the NumberOfPeriods field if non-nil, zero value otherwise.

### GetNumberOfPeriodsOk

`func (o *SubscriptionOfferCodeCreateRequestDataAttributes) GetNumberOfPeriodsOk() (*int32, bool)`

GetNumberOfPeriodsOk returns a tuple with the NumberOfPeriods field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetNumberOfPeriods

`func (o *SubscriptionOfferCodeCreateRequestDataAttributes) SetNumberOfPeriods(v int32)`

SetNumberOfPeriods sets NumberOfPeriods field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


