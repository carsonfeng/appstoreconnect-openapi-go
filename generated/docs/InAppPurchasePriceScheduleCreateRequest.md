# InAppPurchasePriceScheduleCreateRequest

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**InAppPurchasePriceScheduleCreateRequestData**](InAppPurchasePriceScheduleCreateRequestData.md) |  | 
**Included** | Pointer to [**[]InAppPurchasePriceScheduleCreateRequestIncludedInner**](InAppPurchasePriceScheduleCreateRequestIncludedInner.md) |  | [optional] 

## Methods

### NewInAppPurchasePriceScheduleCreateRequest

`func NewInAppPurchasePriceScheduleCreateRequest(data InAppPurchasePriceScheduleCreateRequestData, ) *InAppPurchasePriceScheduleCreateRequest`

NewInAppPurchasePriceScheduleCreateRequest instantiates a new InAppPurchasePriceScheduleCreateRequest object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewInAppPurchasePriceScheduleCreateRequestWithDefaults

`func NewInAppPurchasePriceScheduleCreateRequestWithDefaults() *InAppPurchasePriceScheduleCreateRequest`

NewInAppPurchasePriceScheduleCreateRequestWithDefaults instantiates a new InAppPurchasePriceScheduleCreateRequest object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *InAppPurchasePriceScheduleCreateRequest) GetData() InAppPurchasePriceScheduleCreateRequestData`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *InAppPurchasePriceScheduleCreateRequest) GetDataOk() (*InAppPurchasePriceScheduleCreateRequestData, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *InAppPurchasePriceScheduleCreateRequest) SetData(v InAppPurchasePriceScheduleCreateRequestData)`

SetData sets Data field to given value.


### GetIncluded

`func (o *InAppPurchasePriceScheduleCreateRequest) GetIncluded() []InAppPurchasePriceScheduleCreateRequestIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *InAppPurchasePriceScheduleCreateRequest) GetIncludedOk() (*[]InAppPurchasePriceScheduleCreateRequestIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *InAppPurchasePriceScheduleCreateRequest) SetIncluded(v []InAppPurchasePriceScheduleCreateRequestIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *InAppPurchasePriceScheduleCreateRequest) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


