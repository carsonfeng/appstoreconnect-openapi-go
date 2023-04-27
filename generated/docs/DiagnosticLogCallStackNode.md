# DiagnosticLogCallStackNode

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**SampleCount** | Pointer to **int32** |  | [optional] 
**IsBlameFrame** | Pointer to **bool** |  | [optional] 
**SymbolName** | Pointer to **string** |  | [optional] 
**InsightsCategory** | Pointer to **string** |  | [optional] 
**OffsetIntoSymbol** | Pointer to **string** |  | [optional] 
**BinaryName** | Pointer to **string** |  | [optional] 
**FileName** | Pointer to **string** |  | [optional] 
**BinaryUUID** | Pointer to **string** |  | [optional] 
**LineNumber** | Pointer to **string** |  | [optional] 
**Address** | Pointer to **string** |  | [optional] 
**OffsetIntoBinaryTextSegment** | Pointer to **string** |  | [optional] 
**RawFrame** | Pointer to **string** |  | [optional] 
**SubFrames** | Pointer to [**[]DiagnosticLogCallStackNode**](DiagnosticLogCallStackNode.md) |  | [optional] 

## Methods

### NewDiagnosticLogCallStackNode

`func NewDiagnosticLogCallStackNode() *DiagnosticLogCallStackNode`

NewDiagnosticLogCallStackNode instantiates a new DiagnosticLogCallStackNode object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewDiagnosticLogCallStackNodeWithDefaults

`func NewDiagnosticLogCallStackNodeWithDefaults() *DiagnosticLogCallStackNode`

NewDiagnosticLogCallStackNodeWithDefaults instantiates a new DiagnosticLogCallStackNode object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetSampleCount

`func (o *DiagnosticLogCallStackNode) GetSampleCount() int32`

GetSampleCount returns the SampleCount field if non-nil, zero value otherwise.

### GetSampleCountOk

`func (o *DiagnosticLogCallStackNode) GetSampleCountOk() (*int32, bool)`

GetSampleCountOk returns a tuple with the SampleCount field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSampleCount

`func (o *DiagnosticLogCallStackNode) SetSampleCount(v int32)`

SetSampleCount sets SampleCount field to given value.

### HasSampleCount

`func (o *DiagnosticLogCallStackNode) HasSampleCount() bool`

HasSampleCount returns a boolean if a field has been set.

### GetIsBlameFrame

`func (o *DiagnosticLogCallStackNode) GetIsBlameFrame() bool`

GetIsBlameFrame returns the IsBlameFrame field if non-nil, zero value otherwise.

### GetIsBlameFrameOk

`func (o *DiagnosticLogCallStackNode) GetIsBlameFrameOk() (*bool, bool)`

GetIsBlameFrameOk returns a tuple with the IsBlameFrame field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIsBlameFrame

`func (o *DiagnosticLogCallStackNode) SetIsBlameFrame(v bool)`

SetIsBlameFrame sets IsBlameFrame field to given value.

### HasIsBlameFrame

`func (o *DiagnosticLogCallStackNode) HasIsBlameFrame() bool`

HasIsBlameFrame returns a boolean if a field has been set.

### GetSymbolName

`func (o *DiagnosticLogCallStackNode) GetSymbolName() string`

GetSymbolName returns the SymbolName field if non-nil, zero value otherwise.

### GetSymbolNameOk

`func (o *DiagnosticLogCallStackNode) GetSymbolNameOk() (*string, bool)`

GetSymbolNameOk returns a tuple with the SymbolName field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSymbolName

`func (o *DiagnosticLogCallStackNode) SetSymbolName(v string)`

SetSymbolName sets SymbolName field to given value.

### HasSymbolName

`func (o *DiagnosticLogCallStackNode) HasSymbolName() bool`

HasSymbolName returns a boolean if a field has been set.

### GetInsightsCategory

`func (o *DiagnosticLogCallStackNode) GetInsightsCategory() string`

GetInsightsCategory returns the InsightsCategory field if non-nil, zero value otherwise.

### GetInsightsCategoryOk

`func (o *DiagnosticLogCallStackNode) GetInsightsCategoryOk() (*string, bool)`

GetInsightsCategoryOk returns a tuple with the InsightsCategory field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetInsightsCategory

`func (o *DiagnosticLogCallStackNode) SetInsightsCategory(v string)`

SetInsightsCategory sets InsightsCategory field to given value.

### HasInsightsCategory

`func (o *DiagnosticLogCallStackNode) HasInsightsCategory() bool`

HasInsightsCategory returns a boolean if a field has been set.

### GetOffsetIntoSymbol

`func (o *DiagnosticLogCallStackNode) GetOffsetIntoSymbol() string`

GetOffsetIntoSymbol returns the OffsetIntoSymbol field if non-nil, zero value otherwise.

### GetOffsetIntoSymbolOk

`func (o *DiagnosticLogCallStackNode) GetOffsetIntoSymbolOk() (*string, bool)`

GetOffsetIntoSymbolOk returns a tuple with the OffsetIntoSymbol field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetOffsetIntoSymbol

`func (o *DiagnosticLogCallStackNode) SetOffsetIntoSymbol(v string)`

SetOffsetIntoSymbol sets OffsetIntoSymbol field to given value.

### HasOffsetIntoSymbol

`func (o *DiagnosticLogCallStackNode) HasOffsetIntoSymbol() bool`

HasOffsetIntoSymbol returns a boolean if a field has been set.

### GetBinaryName

`func (o *DiagnosticLogCallStackNode) GetBinaryName() string`

GetBinaryName returns the BinaryName field if non-nil, zero value otherwise.

### GetBinaryNameOk

`func (o *DiagnosticLogCallStackNode) GetBinaryNameOk() (*string, bool)`

GetBinaryNameOk returns a tuple with the BinaryName field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetBinaryName

`func (o *DiagnosticLogCallStackNode) SetBinaryName(v string)`

SetBinaryName sets BinaryName field to given value.

### HasBinaryName

`func (o *DiagnosticLogCallStackNode) HasBinaryName() bool`

HasBinaryName returns a boolean if a field has been set.

### GetFileName

`func (o *DiagnosticLogCallStackNode) GetFileName() string`

GetFileName returns the FileName field if non-nil, zero value otherwise.

### GetFileNameOk

`func (o *DiagnosticLogCallStackNode) GetFileNameOk() (*string, bool)`

GetFileNameOk returns a tuple with the FileName field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFileName

`func (o *DiagnosticLogCallStackNode) SetFileName(v string)`

SetFileName sets FileName field to given value.

### HasFileName

`func (o *DiagnosticLogCallStackNode) HasFileName() bool`

HasFileName returns a boolean if a field has been set.

### GetBinaryUUID

`func (o *DiagnosticLogCallStackNode) GetBinaryUUID() string`

GetBinaryUUID returns the BinaryUUID field if non-nil, zero value otherwise.

### GetBinaryUUIDOk

`func (o *DiagnosticLogCallStackNode) GetBinaryUUIDOk() (*string, bool)`

GetBinaryUUIDOk returns a tuple with the BinaryUUID field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetBinaryUUID

`func (o *DiagnosticLogCallStackNode) SetBinaryUUID(v string)`

SetBinaryUUID sets BinaryUUID field to given value.

### HasBinaryUUID

`func (o *DiagnosticLogCallStackNode) HasBinaryUUID() bool`

HasBinaryUUID returns a boolean if a field has been set.

### GetLineNumber

`func (o *DiagnosticLogCallStackNode) GetLineNumber() string`

GetLineNumber returns the LineNumber field if non-nil, zero value otherwise.

### GetLineNumberOk

`func (o *DiagnosticLogCallStackNode) GetLineNumberOk() (*string, bool)`

GetLineNumberOk returns a tuple with the LineNumber field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLineNumber

`func (o *DiagnosticLogCallStackNode) SetLineNumber(v string)`

SetLineNumber sets LineNumber field to given value.

### HasLineNumber

`func (o *DiagnosticLogCallStackNode) HasLineNumber() bool`

HasLineNumber returns a boolean if a field has been set.

### GetAddress

`func (o *DiagnosticLogCallStackNode) GetAddress() string`

GetAddress returns the Address field if non-nil, zero value otherwise.

### GetAddressOk

`func (o *DiagnosticLogCallStackNode) GetAddressOk() (*string, bool)`

GetAddressOk returns a tuple with the Address field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAddress

`func (o *DiagnosticLogCallStackNode) SetAddress(v string)`

SetAddress sets Address field to given value.

### HasAddress

`func (o *DiagnosticLogCallStackNode) HasAddress() bool`

HasAddress returns a boolean if a field has been set.

### GetOffsetIntoBinaryTextSegment

`func (o *DiagnosticLogCallStackNode) GetOffsetIntoBinaryTextSegment() string`

GetOffsetIntoBinaryTextSegment returns the OffsetIntoBinaryTextSegment field if non-nil, zero value otherwise.

### GetOffsetIntoBinaryTextSegmentOk

`func (o *DiagnosticLogCallStackNode) GetOffsetIntoBinaryTextSegmentOk() (*string, bool)`

GetOffsetIntoBinaryTextSegmentOk returns a tuple with the OffsetIntoBinaryTextSegment field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetOffsetIntoBinaryTextSegment

`func (o *DiagnosticLogCallStackNode) SetOffsetIntoBinaryTextSegment(v string)`

SetOffsetIntoBinaryTextSegment sets OffsetIntoBinaryTextSegment field to given value.

### HasOffsetIntoBinaryTextSegment

`func (o *DiagnosticLogCallStackNode) HasOffsetIntoBinaryTextSegment() bool`

HasOffsetIntoBinaryTextSegment returns a boolean if a field has been set.

### GetRawFrame

`func (o *DiagnosticLogCallStackNode) GetRawFrame() string`

GetRawFrame returns the RawFrame field if non-nil, zero value otherwise.

### GetRawFrameOk

`func (o *DiagnosticLogCallStackNode) GetRawFrameOk() (*string, bool)`

GetRawFrameOk returns a tuple with the RawFrame field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRawFrame

`func (o *DiagnosticLogCallStackNode) SetRawFrame(v string)`

SetRawFrame sets RawFrame field to given value.

### HasRawFrame

`func (o *DiagnosticLogCallStackNode) HasRawFrame() bool`

HasRawFrame returns a boolean if a field has been set.

### GetSubFrames

`func (o *DiagnosticLogCallStackNode) GetSubFrames() []DiagnosticLogCallStackNode`

GetSubFrames returns the SubFrames field if non-nil, zero value otherwise.

### GetSubFramesOk

`func (o *DiagnosticLogCallStackNode) GetSubFramesOk() (*[]DiagnosticLogCallStackNode, bool)`

GetSubFramesOk returns a tuple with the SubFrames field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSubFrames

`func (o *DiagnosticLogCallStackNode) SetSubFrames(v []DiagnosticLogCallStackNode)`

SetSubFrames sets SubFrames field to given value.

### HasSubFrames

`func (o *DiagnosticLogCallStackNode) HasSubFrames() bool`

HasSubFrames returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


