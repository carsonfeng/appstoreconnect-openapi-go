# SubscriptionOfferCodeAttributes

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Name** | Pointer to **string** |  | [optional] 
**CustomerEligibilities** | Pointer to [**[]SubscriptionCustomerEligibility**](SubscriptionCustomerEligibility.md) |  | [optional] 
**OfferEligibility** | Pointer to [**SubscriptionOfferEligibility**](SubscriptionOfferEligibility.md) |  | [optional] 
**Duration** | Pointer to [**SubscriptionOfferDuration**](SubscriptionOfferDuration.md) |  | [optional] 
**OfferMode** | Pointer to [**SubscriptionOfferMode**](SubscriptionOfferMode.md) |  | [optional] 
**NumberOfPeriods** | Pointer to **int32** |  | [optional] 
**TotalNumberOfCodes** | Pointer to **int32** |  | [optional] 
**Active** | Pointer to **bool** |  | [optional] 

## Methods

### NewSubscriptionOfferCodeAttributes

`func NewSubscriptionOfferCodeAttributes() *SubscriptionOfferCodeAttributes`

NewSubscriptionOfferCodeAttributes instantiates a new SubscriptionOfferCodeAttributes object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionOfferCodeAttributesWithDefaults

`func NewSubscriptionOfferCodeAttributesWithDefaults() *SubscriptionOfferCodeAttributes`

NewSubscriptionOfferCodeAttributesWithDefaults instantiates a new SubscriptionOfferCodeAttributes object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetName

`func (o *SubscriptionOfferCodeAttributes) GetName() string`

GetName returns the Name field if non-nil, zero value otherwise.

### GetNameOk

`func (o *SubscriptionOfferCodeAttributes) GetNameOk() (*string, bool)`

GetNameOk returns a tuple with the Name field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetName

`func (o *SubscriptionOfferCodeAttributes) SetName(v string)`

SetName sets Name field to given value.

### HasName

`func (o *SubscriptionOfferCodeAttributes) HasName() bool`

HasName returns a boolean if a field has been set.

### GetCustomerEligibilities

`func (o *SubscriptionOfferCodeAttributes) GetCustomerEligibilities() []SubscriptionCustomerEligibility`

GetCustomerEligibilities returns the CustomerEligibilities field if non-nil, zero value otherwise.

### GetCustomerEligibilitiesOk

`func (o *SubscriptionOfferCodeAttributes) GetCustomerEligibilitiesOk() (*[]SubscriptionCustomerEligibility, bool)`

GetCustomerEligibilitiesOk returns a tuple with the CustomerEligibilities field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCustomerEligibilities

`func (o *SubscriptionOfferCodeAttributes) SetCustomerEligibilities(v []SubscriptionCustomerEligibility)`

SetCustomerEligibilities sets CustomerEligibilities field to given value.

### HasCustomerEligibilities

`func (o *SubscriptionOfferCodeAttributes) HasCustomerEligibilities() bool`

HasCustomerEligibilities returns a boolean if a field has been set.

### GetOfferEligibility

`func (o *SubscriptionOfferCodeAttributes) GetOfferEligibility() SubscriptionOfferEligibility`

GetOfferEligibility returns the OfferEligibility field if non-nil, zero value otherwise.

### GetOfferEligibilityOk

`func (o *SubscriptionOfferCodeAttributes) GetOfferEligibilityOk() (*SubscriptionOfferEligibility, bool)`

GetOfferEligibilityOk returns a tuple with the OfferEligibility field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetOfferEligibility

`func (o *SubscriptionOfferCodeAttributes) SetOfferEligibility(v SubscriptionOfferEligibility)`

SetOfferEligibility sets OfferEligibility field to given value.

### HasOfferEligibility

`func (o *SubscriptionOfferCodeAttributes) HasOfferEligibility() bool`

HasOfferEligibility returns a boolean if a field has been set.

### GetDuration

`func (o *SubscriptionOfferCodeAttributes) GetDuration() SubscriptionOfferDuration`

GetDuration returns the Duration field if non-nil, zero value otherwise.

### GetDurationOk

`func (o *SubscriptionOfferCodeAttributes) GetDurationOk() (*SubscriptionOfferDuration, bool)`

GetDurationOk returns a tuple with the Duration field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDuration

`func (o *SubscriptionOfferCodeAttributes) SetDuration(v SubscriptionOfferDuration)`

SetDuration sets Duration field to given value.

### HasDuration

`func (o *SubscriptionOfferCodeAttributes) HasDuration() bool`

HasDuration returns a boolean if a field has been set.

### GetOfferMode

`func (o *SubscriptionOfferCodeAttributes) GetOfferMode() SubscriptionOfferMode`

GetOfferMode returns the OfferMode field if non-nil, zero value otherwise.

### GetOfferModeOk

`func (o *SubscriptionOfferCodeAttributes) GetOfferModeOk() (*SubscriptionOfferMode, bool)`

GetOfferModeOk returns a tuple with the OfferMode field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetOfferMode

`func (o *SubscriptionOfferCodeAttributes) SetOfferMode(v SubscriptionOfferMode)`

SetOfferMode sets OfferMode field to given value.

### HasOfferMode

`func (o *SubscriptionOfferCodeAttributes) HasOfferMode() bool`

HasOfferMode returns a boolean if a field has been set.

### GetNumberOfPeriods

`func (o *SubscriptionOfferCodeAttributes) GetNumberOfPeriods() int32`

GetNumberOfPeriods returns the NumberOfPeriods field if non-nil, zero value otherwise.

### GetNumberOfPeriodsOk

`func (o *SubscriptionOfferCodeAttributes) GetNumberOfPeriodsOk() (*int32, bool)`

GetNumberOfPeriodsOk returns a tuple with the NumberOfPeriods field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetNumberOfPeriods

`func (o *SubscriptionOfferCodeAttributes) SetNumberOfPeriods(v int32)`

SetNumberOfPeriods sets NumberOfPeriods field to given value.

### HasNumberOfPeriods

`func (o *SubscriptionOfferCodeAttributes) HasNumberOfPeriods() bool`

HasNumberOfPeriods returns a boolean if a field has been set.

### GetTotalNumberOfCodes

`func (o *SubscriptionOfferCodeAttributes) GetTotalNumberOfCodes() int32`

GetTotalNumberOfCodes returns the TotalNumberOfCodes field if non-nil, zero value otherwise.

### GetTotalNumberOfCodesOk

`func (o *SubscriptionOfferCodeAttributes) GetTotalNumberOfCodesOk() (*int32, bool)`

GetTotalNumberOfCodesOk returns a tuple with the TotalNumberOfCodes field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTotalNumberOfCodes

`func (o *SubscriptionOfferCodeAttributes) SetTotalNumberOfCodes(v int32)`

SetTotalNumberOfCodes sets TotalNumberOfCodes field to given value.

### HasTotalNumberOfCodes

`func (o *SubscriptionOfferCodeAttributes) HasTotalNumberOfCodes() bool`

HasTotalNumberOfCodes returns a boolean if a field has been set.

### GetActive

`func (o *SubscriptionOfferCodeAttributes) GetActive() bool`

GetActive returns the Active field if non-nil, zero value otherwise.

### GetActiveOk

`func (o *SubscriptionOfferCodeAttributes) GetActiveOk() (*bool, bool)`

GetActiveOk returns a tuple with the Active field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetActive

`func (o *SubscriptionOfferCodeAttributes) SetActive(v bool)`

SetActive sets Active field to given value.

### HasActive

`func (o *SubscriptionOfferCodeAttributes) HasActive() bool`

HasActive returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


