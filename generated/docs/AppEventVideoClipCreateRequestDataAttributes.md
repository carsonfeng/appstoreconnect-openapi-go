# AppEventVideoClipCreateRequestDataAttributes

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**FileSize** | **int32** |  | 
**FileName** | **string** |  | 
**PreviewFrameTimeCode** | Pointer to **string** |  | [optional] 
**AppEventAssetType** | [**AppEventAssetType**](AppEventAssetType.md) |  | 

## Methods

### NewAppEventVideoClipCreateRequestDataAttributes

`func NewAppEventVideoClipCreateRequestDataAttributes(fileSize int32, fileName string, appEventAssetType AppEventAssetType, ) *AppEventVideoClipCreateRequestDataAttributes`

NewAppEventVideoClipCreateRequestDataAttributes instantiates a new AppEventVideoClipCreateRequestDataAttributes object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppEventVideoClipCreateRequestDataAttributesWithDefaults

`func NewAppEventVideoClipCreateRequestDataAttributesWithDefaults() *AppEventVideoClipCreateRequestDataAttributes`

NewAppEventVideoClipCreateRequestDataAttributesWithDefaults instantiates a new AppEventVideoClipCreateRequestDataAttributes object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetFileSize

`func (o *AppEventVideoClipCreateRequestDataAttributes) GetFileSize() int32`

GetFileSize returns the FileSize field if non-nil, zero value otherwise.

### GetFileSizeOk

`func (o *AppEventVideoClipCreateRequestDataAttributes) GetFileSizeOk() (*int32, bool)`

GetFileSizeOk returns a tuple with the FileSize field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFileSize

`func (o *AppEventVideoClipCreateRequestDataAttributes) SetFileSize(v int32)`

SetFileSize sets FileSize field to given value.


### GetFileName

`func (o *AppEventVideoClipCreateRequestDataAttributes) GetFileName() string`

GetFileName returns the FileName field if non-nil, zero value otherwise.

### GetFileNameOk

`func (o *AppEventVideoClipCreateRequestDataAttributes) GetFileNameOk() (*string, bool)`

GetFileNameOk returns a tuple with the FileName field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFileName

`func (o *AppEventVideoClipCreateRequestDataAttributes) SetFileName(v string)`

SetFileName sets FileName field to given value.


### GetPreviewFrameTimeCode

`func (o *AppEventVideoClipCreateRequestDataAttributes) GetPreviewFrameTimeCode() string`

GetPreviewFrameTimeCode returns the PreviewFrameTimeCode field if non-nil, zero value otherwise.

### GetPreviewFrameTimeCodeOk

`func (o *AppEventVideoClipCreateRequestDataAttributes) GetPreviewFrameTimeCodeOk() (*string, bool)`

GetPreviewFrameTimeCodeOk returns a tuple with the PreviewFrameTimeCode field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPreviewFrameTimeCode

`func (o *AppEventVideoClipCreateRequestDataAttributes) SetPreviewFrameTimeCode(v string)`

SetPreviewFrameTimeCode sets PreviewFrameTimeCode field to given value.

### HasPreviewFrameTimeCode

`func (o *AppEventVideoClipCreateRequestDataAttributes) HasPreviewFrameTimeCode() bool`

HasPreviewFrameTimeCode returns a boolean if a field has been set.

### GetAppEventAssetType

`func (o *AppEventVideoClipCreateRequestDataAttributes) GetAppEventAssetType() AppEventAssetType`

GetAppEventAssetType returns the AppEventAssetType field if non-nil, zero value otherwise.

### GetAppEventAssetTypeOk

`func (o *AppEventVideoClipCreateRequestDataAttributes) GetAppEventAssetTypeOk() (*AppEventAssetType, bool)`

GetAppEventAssetTypeOk returns a tuple with the AppEventAssetType field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAppEventAssetType

`func (o *AppEventVideoClipCreateRequestDataAttributes) SetAppEventAssetType(v AppEventAssetType)`

SetAppEventAssetType sets AppEventAssetType field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


