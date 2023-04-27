# AppPriceScheduleResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**AppPriceSchedule**](AppPriceSchedule.md) |  | 
**Included** | Pointer to [**[]AppPriceScheduleResponseIncludedInner**](AppPriceScheduleResponseIncludedInner.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewAppPriceScheduleResponse

`func NewAppPriceScheduleResponse(data AppPriceSchedule, links DocumentLinks, ) *AppPriceScheduleResponse`

NewAppPriceScheduleResponse instantiates a new AppPriceScheduleResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppPriceScheduleResponseWithDefaults

`func NewAppPriceScheduleResponseWithDefaults() *AppPriceScheduleResponse`

NewAppPriceScheduleResponseWithDefaults instantiates a new AppPriceScheduleResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *AppPriceScheduleResponse) GetData() AppPriceSchedule`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *AppPriceScheduleResponse) GetDataOk() (*AppPriceSchedule, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *AppPriceScheduleResponse) SetData(v AppPriceSchedule)`

SetData sets Data field to given value.


### GetIncluded

`func (o *AppPriceScheduleResponse) GetIncluded() []AppPriceScheduleResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *AppPriceScheduleResponse) GetIncludedOk() (*[]AppPriceScheduleResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *AppPriceScheduleResponse) SetIncluded(v []AppPriceScheduleResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *AppPriceScheduleResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *AppPriceScheduleResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppPriceScheduleResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppPriceScheduleResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


