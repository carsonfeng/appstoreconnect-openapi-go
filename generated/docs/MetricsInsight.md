# MetricsInsight

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**MetricCategory** | Pointer to [**MetricCategory**](MetricCategory.md) |  | [optional] 
**LatestVersion** | Pointer to **string** |  | [optional] 
**Metric** | Pointer to **string** |  | [optional] 
**SummaryString** | Pointer to **string** |  | [optional] 
**ReferenceVersions** | Pointer to **string** |  | [optional] 
**MaxLatestVersionValue** | Pointer to **float32** |  | [optional] 
**SubSystemLabel** | Pointer to **string** |  | [optional] 
**HighImpact** | Pointer to **bool** |  | [optional] 
**Populations** | Pointer to [**[]MetricsInsightPopulationsInner**](MetricsInsightPopulationsInner.md) |  | [optional] 

## Methods

### NewMetricsInsight

`func NewMetricsInsight() *MetricsInsight`

NewMetricsInsight instantiates a new MetricsInsight object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewMetricsInsightWithDefaults

`func NewMetricsInsightWithDefaults() *MetricsInsight`

NewMetricsInsightWithDefaults instantiates a new MetricsInsight object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetMetricCategory

`func (o *MetricsInsight) GetMetricCategory() MetricCategory`

GetMetricCategory returns the MetricCategory field if non-nil, zero value otherwise.

### GetMetricCategoryOk

`func (o *MetricsInsight) GetMetricCategoryOk() (*MetricCategory, bool)`

GetMetricCategoryOk returns a tuple with the MetricCategory field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMetricCategory

`func (o *MetricsInsight) SetMetricCategory(v MetricCategory)`

SetMetricCategory sets MetricCategory field to given value.

### HasMetricCategory

`func (o *MetricsInsight) HasMetricCategory() bool`

HasMetricCategory returns a boolean if a field has been set.

### GetLatestVersion

`func (o *MetricsInsight) GetLatestVersion() string`

GetLatestVersion returns the LatestVersion field if non-nil, zero value otherwise.

### GetLatestVersionOk

`func (o *MetricsInsight) GetLatestVersionOk() (*string, bool)`

GetLatestVersionOk returns a tuple with the LatestVersion field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLatestVersion

`func (o *MetricsInsight) SetLatestVersion(v string)`

SetLatestVersion sets LatestVersion field to given value.

### HasLatestVersion

`func (o *MetricsInsight) HasLatestVersion() bool`

HasLatestVersion returns a boolean if a field has been set.

### GetMetric

`func (o *MetricsInsight) GetMetric() string`

GetMetric returns the Metric field if non-nil, zero value otherwise.

### GetMetricOk

`func (o *MetricsInsight) GetMetricOk() (*string, bool)`

GetMetricOk returns a tuple with the Metric field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMetric

`func (o *MetricsInsight) SetMetric(v string)`

SetMetric sets Metric field to given value.

### HasMetric

`func (o *MetricsInsight) HasMetric() bool`

HasMetric returns a boolean if a field has been set.

### GetSummaryString

`func (o *MetricsInsight) GetSummaryString() string`

GetSummaryString returns the SummaryString field if non-nil, zero value otherwise.

### GetSummaryStringOk

`func (o *MetricsInsight) GetSummaryStringOk() (*string, bool)`

GetSummaryStringOk returns a tuple with the SummaryString field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSummaryString

`func (o *MetricsInsight) SetSummaryString(v string)`

SetSummaryString sets SummaryString field to given value.

### HasSummaryString

`func (o *MetricsInsight) HasSummaryString() bool`

HasSummaryString returns a boolean if a field has been set.

### GetReferenceVersions

`func (o *MetricsInsight) GetReferenceVersions() string`

GetReferenceVersions returns the ReferenceVersions field if non-nil, zero value otherwise.

### GetReferenceVersionsOk

`func (o *MetricsInsight) GetReferenceVersionsOk() (*string, bool)`

GetReferenceVersionsOk returns a tuple with the ReferenceVersions field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetReferenceVersions

`func (o *MetricsInsight) SetReferenceVersions(v string)`

SetReferenceVersions sets ReferenceVersions field to given value.

### HasReferenceVersions

`func (o *MetricsInsight) HasReferenceVersions() bool`

HasReferenceVersions returns a boolean if a field has been set.

### GetMaxLatestVersionValue

`func (o *MetricsInsight) GetMaxLatestVersionValue() float32`

GetMaxLatestVersionValue returns the MaxLatestVersionValue field if non-nil, zero value otherwise.

### GetMaxLatestVersionValueOk

`func (o *MetricsInsight) GetMaxLatestVersionValueOk() (*float32, bool)`

GetMaxLatestVersionValueOk returns a tuple with the MaxLatestVersionValue field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMaxLatestVersionValue

`func (o *MetricsInsight) SetMaxLatestVersionValue(v float32)`

SetMaxLatestVersionValue sets MaxLatestVersionValue field to given value.

### HasMaxLatestVersionValue

`func (o *MetricsInsight) HasMaxLatestVersionValue() bool`

HasMaxLatestVersionValue returns a boolean if a field has been set.

### GetSubSystemLabel

`func (o *MetricsInsight) GetSubSystemLabel() string`

GetSubSystemLabel returns the SubSystemLabel field if non-nil, zero value otherwise.

### GetSubSystemLabelOk

`func (o *MetricsInsight) GetSubSystemLabelOk() (*string, bool)`

GetSubSystemLabelOk returns a tuple with the SubSystemLabel field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSubSystemLabel

`func (o *MetricsInsight) SetSubSystemLabel(v string)`

SetSubSystemLabel sets SubSystemLabel field to given value.

### HasSubSystemLabel

`func (o *MetricsInsight) HasSubSystemLabel() bool`

HasSubSystemLabel returns a boolean if a field has been set.

### GetHighImpact

`func (o *MetricsInsight) GetHighImpact() bool`

GetHighImpact returns the HighImpact field if non-nil, zero value otherwise.

### GetHighImpactOk

`func (o *MetricsInsight) GetHighImpactOk() (*bool, bool)`

GetHighImpactOk returns a tuple with the HighImpact field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetHighImpact

`func (o *MetricsInsight) SetHighImpact(v bool)`

SetHighImpact sets HighImpact field to given value.

### HasHighImpact

`func (o *MetricsInsight) HasHighImpact() bool`

HasHighImpact returns a boolean if a field has been set.

### GetPopulations

`func (o *MetricsInsight) GetPopulations() []MetricsInsightPopulationsInner`

GetPopulations returns the Populations field if non-nil, zero value otherwise.

### GetPopulationsOk

`func (o *MetricsInsight) GetPopulationsOk() (*[]MetricsInsightPopulationsInner, bool)`

GetPopulationsOk returns a tuple with the Populations field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPopulations

`func (o *MetricsInsight) SetPopulations(v []MetricsInsightPopulationsInner)`

SetPopulations sets Populations field to given value.

### HasPopulations

`func (o *MetricsInsight) HasPopulations() bool`

HasPopulations returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


