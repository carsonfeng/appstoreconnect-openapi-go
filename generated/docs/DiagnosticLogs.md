# DiagnosticLogs

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**ProductData** | Pointer to [**[]DiagnosticLogsProductDataInner**](DiagnosticLogsProductDataInner.md) |  | [optional] 
**Version** | Pointer to **string** |  | [optional] 

## Methods

### NewDiagnosticLogs

`func NewDiagnosticLogs() *DiagnosticLogs`

NewDiagnosticLogs instantiates a new DiagnosticLogs object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewDiagnosticLogsWithDefaults

`func NewDiagnosticLogsWithDefaults() *DiagnosticLogs`

NewDiagnosticLogsWithDefaults instantiates a new DiagnosticLogs object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetProductData

`func (o *DiagnosticLogs) GetProductData() []DiagnosticLogsProductDataInner`

GetProductData returns the ProductData field if non-nil, zero value otherwise.

### GetProductDataOk

`func (o *DiagnosticLogs) GetProductDataOk() (*[]DiagnosticLogsProductDataInner, bool)`

GetProductDataOk returns a tuple with the ProductData field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetProductData

`func (o *DiagnosticLogs) SetProductData(v []DiagnosticLogsProductDataInner)`

SetProductData sets ProductData field to given value.

### HasProductData

`func (o *DiagnosticLogs) HasProductData() bool`

HasProductData returns a boolean if a field has been set.

### GetVersion

`func (o *DiagnosticLogs) GetVersion() string`

GetVersion returns the Version field if non-nil, zero value otherwise.

### GetVersionOk

`func (o *DiagnosticLogs) GetVersionOk() (*string, bool)`

GetVersionOk returns a tuple with the Version field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetVersion

`func (o *DiagnosticLogs) SetVersion(v string)`

SetVersion sets Version field to given value.

### HasVersion

`func (o *DiagnosticLogs) HasVersion() bool`

HasVersion returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


