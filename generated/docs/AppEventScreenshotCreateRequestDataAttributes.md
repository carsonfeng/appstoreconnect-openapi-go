# AppEventScreenshotCreateRequestDataAttributes

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**FileSize** | **int32** |  | 
**FileName** | **string** |  | 
**AppEventAssetType** | [**AppEventAssetType**](AppEventAssetType.md) |  | 

## Methods

### NewAppEventScreenshotCreateRequestDataAttributes

`func NewAppEventScreenshotCreateRequestDataAttributes(fileSize int32, fileName string, appEventAssetType AppEventAssetType, ) *AppEventScreenshotCreateRequestDataAttributes`

NewAppEventScreenshotCreateRequestDataAttributes instantiates a new AppEventScreenshotCreateRequestDataAttributes object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppEventScreenshotCreateRequestDataAttributesWithDefaults

`func NewAppEventScreenshotCreateRequestDataAttributesWithDefaults() *AppEventScreenshotCreateRequestDataAttributes`

NewAppEventScreenshotCreateRequestDataAttributesWithDefaults instantiates a new AppEventScreenshotCreateRequestDataAttributes object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetFileSize

`func (o *AppEventScreenshotCreateRequestDataAttributes) GetFileSize() int32`

GetFileSize returns the FileSize field if non-nil, zero value otherwise.

### GetFileSizeOk

`func (o *AppEventScreenshotCreateRequestDataAttributes) GetFileSizeOk() (*int32, bool)`

GetFileSizeOk returns a tuple with the FileSize field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFileSize

`func (o *AppEventScreenshotCreateRequestDataAttributes) SetFileSize(v int32)`

SetFileSize sets FileSize field to given value.


### GetFileName

`func (o *AppEventScreenshotCreateRequestDataAttributes) GetFileName() string`

GetFileName returns the FileName field if non-nil, zero value otherwise.

### GetFileNameOk

`func (o *AppEventScreenshotCreateRequestDataAttributes) GetFileNameOk() (*string, bool)`

GetFileNameOk returns a tuple with the FileName field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFileName

`func (o *AppEventScreenshotCreateRequestDataAttributes) SetFileName(v string)`

SetFileName sets FileName field to given value.


### GetAppEventAssetType

`func (o *AppEventScreenshotCreateRequestDataAttributes) GetAppEventAssetType() AppEventAssetType`

GetAppEventAssetType returns the AppEventAssetType field if non-nil, zero value otherwise.

### GetAppEventAssetTypeOk

`func (o *AppEventScreenshotCreateRequestDataAttributes) GetAppEventAssetTypeOk() (*AppEventAssetType, bool)`

GetAppEventAssetTypeOk returns a tuple with the AppEventAssetType field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAppEventAssetType

`func (o *AppEventScreenshotCreateRequestDataAttributes) SetAppEventAssetType(v AppEventAssetType)`

SetAppEventAssetType sets AppEventAssetType field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


