# SubscriptionUpdateRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**SubscriptionUpdateRequestData**](SubscriptionUpdateRequestData.md) |  | 
**Included** | Pointer to [**[]SubscriptionUpdateRequestIncludedInner**](SubscriptionUpdateRequestIncludedInner.md) |  | [optional] 

## Methods

### NewSubscriptionUpdateRequest

`func NewSubscriptionUpdateRequest(data SubscriptionUpdateRequestData, ) *SubscriptionUpdateRequest`

NewSubscriptionUpdateRequest instantiates a new SubscriptionUpdateRequest object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSubscriptionUpdateRequestWithDefaults

`func NewSubscriptionUpdateRequestWithDefaults() *SubscriptionUpdateRequest`

NewSubscriptionUpdateRequestWithDefaults instantiates a new SubscriptionUpdateRequest object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *SubscriptionUpdateRequest) GetData() SubscriptionUpdateRequestData`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *SubscriptionUpdateRequest) GetDataOk() (*SubscriptionUpdateRequestData, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *SubscriptionUpdateRequest) SetData(v SubscriptionUpdateRequestData)`

SetData sets Data field to given value.


### GetIncluded

`func (o *SubscriptionUpdateRequest) GetIncluded() []SubscriptionUpdateRequestIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *SubscriptionUpdateRequest) GetIncludedOk() (*[]SubscriptionUpdateRequestIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *SubscriptionUpdateRequest) SetIncluded(v []SubscriptionUpdateRequestIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *SubscriptionUpdateRequest) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


