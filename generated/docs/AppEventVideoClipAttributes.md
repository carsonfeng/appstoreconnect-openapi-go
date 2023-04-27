# AppEventVideoClipAttributes

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**FileSize** | Pointer to **int32** |  | [optional] 
**FileName** | Pointer to **string** |  | [optional] 
**PreviewFrameTimeCode** | Pointer to **string** |  | [optional] 
**VideoUrl** | Pointer to **string** |  | [optional] 
**PreviewImage** | Pointer to [**ImageAsset**](ImageAsset.md) |  | [optional] 
**UploadOperations** | Pointer to [**[]UploadOperation**](UploadOperation.md) |  | [optional] 
**AssetDeliveryState** | Pointer to [**AppMediaAssetState**](AppMediaAssetState.md) |  | [optional] 
**AppEventAssetType** | Pointer to [**AppEventAssetType**](AppEventAssetType.md) |  | [optional] 

## Methods

### NewAppEventVideoClipAttributes

`func NewAppEventVideoClipAttributes() *AppEventVideoClipAttributes`

NewAppEventVideoClipAttributes instantiates a new AppEventVideoClipAttributes object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppEventVideoClipAttributesWithDefaults

`func NewAppEventVideoClipAttributesWithDefaults() *AppEventVideoClipAttributes`

NewAppEventVideoClipAttributesWithDefaults instantiates a new AppEventVideoClipAttributes object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetFileSize

`func (o *AppEventVideoClipAttributes) GetFileSize() int32`

GetFileSize returns the FileSize field if non-nil, zero value otherwise.

### GetFileSizeOk

`func (o *AppEventVideoClipAttributes) GetFileSizeOk() (*int32, bool)`

GetFileSizeOk returns a tuple with the FileSize field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFileSize

`func (o *AppEventVideoClipAttributes) SetFileSize(v int32)`

SetFileSize sets FileSize field to given value.

### HasFileSize

`func (o *AppEventVideoClipAttributes) HasFileSize() bool`

HasFileSize returns a boolean if a field has been set.

### GetFileName

`func (o *AppEventVideoClipAttributes) GetFileName() string`

GetFileName returns the FileName field if non-nil, zero value otherwise.

### GetFileNameOk

`func (o *AppEventVideoClipAttributes) GetFileNameOk() (*string, bool)`

GetFileNameOk returns a tuple with the FileName field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFileName

`func (o *AppEventVideoClipAttributes) SetFileName(v string)`

SetFileName sets FileName field to given value.

### HasFileName

`func (o *AppEventVideoClipAttributes) HasFileName() bool`

HasFileName returns a boolean if a field has been set.

### GetPreviewFrameTimeCode

`func (o *AppEventVideoClipAttributes) GetPreviewFrameTimeCode() string`

GetPreviewFrameTimeCode returns the PreviewFrameTimeCode field if non-nil, zero value otherwise.

### GetPreviewFrameTimeCodeOk

`func (o *AppEventVideoClipAttributes) GetPreviewFrameTimeCodeOk() (*string, bool)`

GetPreviewFrameTimeCodeOk returns a tuple with the PreviewFrameTimeCode field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPreviewFrameTimeCode

`func (o *AppEventVideoClipAttributes) SetPreviewFrameTimeCode(v string)`

SetPreviewFrameTimeCode sets PreviewFrameTimeCode field to given value.

### HasPreviewFrameTimeCode

`func (o *AppEventVideoClipAttributes) HasPreviewFrameTimeCode() bool`

HasPreviewFrameTimeCode returns a boolean if a field has been set.

### GetVideoUrl

`func (o *AppEventVideoClipAttributes) GetVideoUrl() string`

GetVideoUrl returns the VideoUrl field if non-nil, zero value otherwise.

### GetVideoUrlOk

`func (o *AppEventVideoClipAttributes) GetVideoUrlOk() (*string, bool)`

GetVideoUrlOk returns a tuple with the VideoUrl field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetVideoUrl

`func (o *AppEventVideoClipAttributes) SetVideoUrl(v string)`

SetVideoUrl sets VideoUrl field to given value.

### HasVideoUrl

`func (o *AppEventVideoClipAttributes) HasVideoUrl() bool`

HasVideoUrl returns a boolean if a field has been set.

### GetPreviewImage

`func (o *AppEventVideoClipAttributes) GetPreviewImage() ImageAsset`

GetPreviewImage returns the PreviewImage field if non-nil, zero value otherwise.

### GetPreviewImageOk

`func (o *AppEventVideoClipAttributes) GetPreviewImageOk() (*ImageAsset, bool)`

GetPreviewImageOk returns a tuple with the PreviewImage field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPreviewImage

`func (o *AppEventVideoClipAttributes) SetPreviewImage(v ImageAsset)`

SetPreviewImage sets PreviewImage field to given value.

### HasPreviewImage

`func (o *AppEventVideoClipAttributes) HasPreviewImage() bool`

HasPreviewImage returns a boolean if a field has been set.

### GetUploadOperations

`func (o *AppEventVideoClipAttributes) GetUploadOperations() []UploadOperation`

GetUploadOperations returns the UploadOperations field if non-nil, zero value otherwise.

### GetUploadOperationsOk

`func (o *AppEventVideoClipAttributes) GetUploadOperationsOk() (*[]UploadOperation, bool)`

GetUploadOperationsOk returns a tuple with the UploadOperations field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetUploadOperations

`func (o *AppEventVideoClipAttributes) SetUploadOperations(v []UploadOperation)`

SetUploadOperations sets UploadOperations field to given value.

### HasUploadOperations

`func (o *AppEventVideoClipAttributes) HasUploadOperations() bool`

HasUploadOperations returns a boolean if a field has been set.

### GetAssetDeliveryState

`func (o *AppEventVideoClipAttributes) GetAssetDeliveryState() AppMediaAssetState`

GetAssetDeliveryState returns the AssetDeliveryState field if non-nil, zero value otherwise.

### GetAssetDeliveryStateOk

`func (o *AppEventVideoClipAttributes) GetAssetDeliveryStateOk() (*AppMediaAssetState, bool)`

GetAssetDeliveryStateOk returns a tuple with the AssetDeliveryState field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAssetDeliveryState

`func (o *AppEventVideoClipAttributes) SetAssetDeliveryState(v AppMediaAssetState)`

SetAssetDeliveryState sets AssetDeliveryState field to given value.

### HasAssetDeliveryState

`func (o *AppEventVideoClipAttributes) HasAssetDeliveryState() bool`

HasAssetDeliveryState returns a boolean if a field has been set.

### GetAppEventAssetType

`func (o *AppEventVideoClipAttributes) GetAppEventAssetType() AppEventAssetType`

GetAppEventAssetType returns the AppEventAssetType field if non-nil, zero value otherwise.

### GetAppEventAssetTypeOk

`func (o *AppEventVideoClipAttributes) GetAppEventAssetTypeOk() (*AppEventAssetType, bool)`

GetAppEventAssetTypeOk returns a tuple with the AppEventAssetType field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAppEventAssetType

`func (o *AppEventVideoClipAttributes) SetAppEventAssetType(v AppEventAssetType)`

SetAppEventAssetType sets AppEventAssetType field to given value.

### HasAppEventAssetType

`func (o *AppEventVideoClipAttributes) HasAppEventAssetType() bool`

HasAppEventAssetType returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


