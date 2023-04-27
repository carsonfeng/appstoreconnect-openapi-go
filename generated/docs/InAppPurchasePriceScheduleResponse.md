# InAppPurchasePriceScheduleResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**InAppPurchasePriceSchedule**](InAppPurchasePriceSchedule.md) |  | 
**Included** | Pointer to [**[]InAppPurchasePriceScheduleResponseIncludedInner**](InAppPurchasePriceScheduleResponseIncludedInner.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewInAppPurchasePriceScheduleResponse

`func NewInAppPurchasePriceScheduleResponse(data InAppPurchasePriceSchedule, links DocumentLinks, ) *InAppPurchasePriceScheduleResponse`

NewInAppPurchasePriceScheduleResponse instantiates a new InAppPurchasePriceScheduleResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewInAppPurchasePriceScheduleResponseWithDefaults

`func NewInAppPurchasePriceScheduleResponseWithDefaults() *InAppPurchasePriceScheduleResponse`

NewInAppPurchasePriceScheduleResponseWithDefaults instantiates a new InAppPurchasePriceScheduleResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *InAppPurchasePriceScheduleResponse) GetData() InAppPurchasePriceSchedule`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *InAppPurchasePriceScheduleResponse) GetDataOk() (*InAppPurchasePriceSchedule, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *InAppPurchasePriceScheduleResponse) SetData(v InAppPurchasePriceSchedule)`

SetData sets Data field to given value.


### GetIncluded

`func (o *InAppPurchasePriceScheduleResponse) GetIncluded() []InAppPurchasePriceScheduleResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *InAppPurchasePriceScheduleResponse) GetIncludedOk() (*[]InAppPurchasePriceScheduleResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *InAppPurchasePriceScheduleResponse) SetIncluded(v []InAppPurchasePriceScheduleResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *InAppPurchasePriceScheduleResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *InAppPurchasePriceScheduleResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *InAppPurchasePriceScheduleResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *InAppPurchasePriceScheduleResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


