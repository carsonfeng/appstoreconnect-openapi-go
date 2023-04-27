# AppEventScreenshotAttributes

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**FileSize** | Pointer to **int32** |  | [optional] 
**FileName** | Pointer to **string** |  | [optional] 
**ImageAsset** | Pointer to [**ImageAsset**](ImageAsset.md) |  | [optional] 
**AssetToken** | Pointer to **string** |  | [optional] 
**UploadOperations** | Pointer to [**[]UploadOperation**](UploadOperation.md) |  | [optional] 
**AssetDeliveryState** | Pointer to [**AppMediaAssetState**](AppMediaAssetState.md) |  | [optional] 
**AppEventAssetType** | Pointer to [**AppEventAssetType**](AppEventAssetType.md) |  | [optional] 

## Methods

### NewAppEventScreenshotAttributes

`func NewAppEventScreenshotAttributes() *AppEventScreenshotAttributes`

NewAppEventScreenshotAttributes instantiates a new AppEventScreenshotAttributes object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppEventScreenshotAttributesWithDefaults

`func NewAppEventScreenshotAttributesWithDefaults() *AppEventScreenshotAttributes`

NewAppEventScreenshotAttributesWithDefaults instantiates a new AppEventScreenshotAttributes object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetFileSize

`func (o *AppEventScreenshotAttributes) GetFileSize() int32`

GetFileSize returns the FileSize field if non-nil, zero value otherwise.

### GetFileSizeOk

`func (o *AppEventScreenshotAttributes) GetFileSizeOk() (*int32, bool)`

GetFileSizeOk returns a tuple with the FileSize field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFileSize

`func (o *AppEventScreenshotAttributes) SetFileSize(v int32)`

SetFileSize sets FileSize field to given value.

### HasFileSize

`func (o *AppEventScreenshotAttributes) HasFileSize() bool`

HasFileSize returns a boolean if a field has been set.

### GetFileName

`func (o *AppEventScreenshotAttributes) GetFileName() string`

GetFileName returns the FileName field if non-nil, zero value otherwise.

### GetFileNameOk

`func (o *AppEventScreenshotAttributes) GetFileNameOk() (*string, bool)`

GetFileNameOk returns a tuple with the FileName field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFileName

`func (o *AppEventScreenshotAttributes) SetFileName(v string)`

SetFileName sets FileName field to given value.

### HasFileName

`func (o *AppEventScreenshotAttributes) HasFileName() bool`

HasFileName returns a boolean if a field has been set.

### GetImageAsset

`func (o *AppEventScreenshotAttributes) GetImageAsset() ImageAsset`

GetImageAsset returns the ImageAsset field if non-nil, zero value otherwise.

### GetImageAssetOk

`func (o *AppEventScreenshotAttributes) GetImageAssetOk() (*ImageAsset, bool)`

GetImageAssetOk returns a tuple with the ImageAsset field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetImageAsset

`func (o *AppEventScreenshotAttributes) SetImageAsset(v ImageAsset)`

SetImageAsset sets ImageAsset field to given value.

### HasImageAsset

`func (o *AppEventScreenshotAttributes) HasImageAsset() bool`

HasImageAsset returns a boolean if a field has been set.

### GetAssetToken

`func (o *AppEventScreenshotAttributes) GetAssetToken() string`

GetAssetToken returns the AssetToken field if non-nil, zero value otherwise.

### GetAssetTokenOk

`func (o *AppEventScreenshotAttributes) GetAssetTokenOk() (*string, bool)`

GetAssetTokenOk returns a tuple with the AssetToken field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAssetToken

`func (o *AppEventScreenshotAttributes) SetAssetToken(v string)`

SetAssetToken sets AssetToken field to given value.

### HasAssetToken

`func (o *AppEventScreenshotAttributes) HasAssetToken() bool`

HasAssetToken returns a boolean if a field has been set.

### GetUploadOperations

`func (o *AppEventScreenshotAttributes) GetUploadOperations() []UploadOperation`

GetUploadOperations returns the UploadOperations field if non-nil, zero value otherwise.

### GetUploadOperationsOk

`func (o *AppEventScreenshotAttributes) GetUploadOperationsOk() (*[]UploadOperation, bool)`

GetUploadOperationsOk returns a tuple with the UploadOperations field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetUploadOperations

`func (o *AppEventScreenshotAttributes) SetUploadOperations(v []UploadOperation)`

SetUploadOperations sets UploadOperations field to given value.

### HasUploadOperations

`func (o *AppEventScreenshotAttributes) HasUploadOperations() bool`

HasUploadOperations returns a boolean if a field has been set.

### GetAssetDeliveryState

`func (o *AppEventScreenshotAttributes) GetAssetDeliveryState() AppMediaAssetState`

GetAssetDeliveryState returns the AssetDeliveryState field if non-nil, zero value otherwise.

### GetAssetDeliveryStateOk

`func (o *AppEventScreenshotAttributes) GetAssetDeliveryStateOk() (*AppMediaAssetState, bool)`

GetAssetDeliveryStateOk returns a tuple with the AssetDeliveryState field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAssetDeliveryState

`func (o *AppEventScreenshotAttributes) SetAssetDeliveryState(v AppMediaAssetState)`

SetAssetDeliveryState sets AssetDeliveryState field to given value.

### HasAssetDeliveryState

`func (o *AppEventScreenshotAttributes) HasAssetDeliveryState() bool`

HasAssetDeliveryState returns a boolean if a field has been set.

### GetAppEventAssetType

`func (o *AppEventScreenshotAttributes) GetAppEventAssetType() AppEventAssetType`

GetAppEventAssetType returns the AppEventAssetType field if non-nil, zero value otherwise.

### GetAppEventAssetTypeOk

`func (o *AppEventScreenshotAttributes) GetAppEventAssetTypeOk() (*AppEventAssetType, bool)`

GetAppEventAssetTypeOk returns a tuple with the AppEventAssetType field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAppEventAssetType

`func (o *AppEventScreenshotAttributes) SetAppEventAssetType(v AppEventAssetType)`

SetAppEventAssetType sets AppEventAssetType field to given value.

### HasAppEventAssetType

`func (o *AppEventScreenshotAttributes) HasAppEventAssetType() bool`

HasAppEventAssetType returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


