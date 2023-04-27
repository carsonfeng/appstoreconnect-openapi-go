# XcodeMetrics

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Version** | Pointer to **string** |  | [optional] 
**Insights** | Pointer to [**XcodeMetricsInsights**](XcodeMetricsInsights.md) |  | [optional] 
**ProductData** | Pointer to [**[]XcodeMetricsProductDataInner**](XcodeMetricsProductDataInner.md) |  | [optional] 

## Methods

### NewXcodeMetrics

`func NewXcodeMetrics() *XcodeMetrics`

NewXcodeMetrics instantiates a new XcodeMetrics object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewXcodeMetricsWithDefaults

`func NewXcodeMetricsWithDefaults() *XcodeMetrics`

NewXcodeMetricsWithDefaults instantiates a new XcodeMetrics object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetVersion

`func (o *XcodeMetrics) GetVersion() string`

GetVersion returns the Version field if non-nil, zero value otherwise.

### GetVersionOk

`func (o *XcodeMetrics) GetVersionOk() (*string, bool)`

GetVersionOk returns a tuple with the Version field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetVersion

`func (o *XcodeMetrics) SetVersion(v string)`

SetVersion sets Version field to given value.

### HasVersion

`func (o *XcodeMetrics) HasVersion() bool`

HasVersion returns a boolean if a field has been set.

### GetInsights

`func (o *XcodeMetrics) GetInsights() XcodeMetricsInsights`

GetInsights returns the Insights field if non-nil, zero value otherwise.

### GetInsightsOk

`func (o *XcodeMetrics) GetInsightsOk() (*XcodeMetricsInsights, bool)`

GetInsightsOk returns a tuple with the Insights field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetInsights

`func (o *XcodeMetrics) SetInsights(v XcodeMetricsInsights)`

SetInsights sets Insights field to given value.

### HasInsights

`func (o *XcodeMetrics) HasInsights() bool`

HasInsights returns a boolean if a field has been set.

### GetProductData

`func (o *XcodeMetrics) GetProductData() []XcodeMetricsProductDataInner`

GetProductData returns the ProductData field if non-nil, zero value otherwise.

### GetProductDataOk

`func (o *XcodeMetrics) GetProductDataOk() (*[]XcodeMetricsProductDataInner, bool)`

GetProductDataOk returns a tuple with the ProductData field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetProductData

`func (o *XcodeMetrics) SetProductData(v []XcodeMetricsProductDataInner)`

SetProductData sets ProductData field to given value.

### HasProductData

`func (o *XcodeMetrics) HasProductData() bool`

HasProductData returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


