# FileLocation

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Path** | Pointer to **string** |  | [optional] 
**LineNumber** | Pointer to **int32** |  | [optional] 

## Methods

### NewFileLocation

`func NewFileLocation() *FileLocation`

NewFileLocation instantiates a new FileLocation object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewFileLocationWithDefaults

`func NewFileLocationWithDefaults() *FileLocation`

NewFileLocationWithDefaults instantiates a new FileLocation object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetPath

`func (o *FileLocation) GetPath() string`

GetPath returns the Path field if non-nil, zero value otherwise.

### GetPathOk

`func (o *FileLocation) GetPathOk() (*string, bool)`

GetPathOk returns a tuple with the Path field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPath

`func (o *FileLocation) SetPath(v string)`

SetPath sets Path field to given value.

### HasPath

`func (o *FileLocation) HasPath() bool`

HasPath returns a boolean if a field has been set.

### GetLineNumber

`func (o *FileLocation) GetLineNumber() int32`

GetLineNumber returns the LineNumber field if non-nil, zero value otherwise.

### GetLineNumberOk

`func (o *FileLocation) GetLineNumberOk() (*int32, bool)`

GetLineNumberOk returns a tuple with the LineNumber field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLineNumber

`func (o *FileLocation) SetLineNumber(v int32)`

SetLineNumber sets LineNumber field to given value.

### HasLineNumber

`func (o *FileLocation) HasLineNumber() bool`

HasLineNumber returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


