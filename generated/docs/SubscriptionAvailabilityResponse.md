# SubscriptionAvailabilityResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**SubscriptionAvailability**](SubscriptionAvailability.md) |  | 
**Included** | Pointer to [**[]SubscriptionAvailabilityResponseIncludedInner**](SubscriptionAvailabilityResponseIncludedInner.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewSubscriptionAvailabilityResponse

`func NewSubscriptionAvailabilityResponse(data SubscriptionAvailability, links DocumentLinks, ) *SubscriptionAvailabilityResponse`

NewSubscriptionAvailabilityResponse instantiates a new SubscriptionAvailabilityResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionAvailabilityResponseWithDefaults

`func NewSubscriptionAvailabilityResponseWithDefaults() *SubscriptionAvailabilityResponse`

NewSubscriptionAvailabilityResponseWithDefaults instantiates a new SubscriptionAvailabilityResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *SubscriptionAvailabilityResponse) GetData() SubscriptionAvailability`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *SubscriptionAvailabilityResponse) GetDataOk() (*SubscriptionAvailability, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *SubscriptionAvailabilityResponse) SetData(v SubscriptionAvailability)`

SetData sets Data field to given value.


### GetIncluded

`func (o *SubscriptionAvailabilityResponse) GetIncluded() []SubscriptionAvailabilityResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *SubscriptionAvailabilityResponse) GetIncludedOk() (*[]SubscriptionAvailabilityResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *SubscriptionAvailabilityResponse) SetIncluded(v []SubscriptionAvailabilityResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *SubscriptionAvailabilityResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *SubscriptionAvailabilityResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *SubscriptionAvailabilityResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *SubscriptionAvailabilityResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


