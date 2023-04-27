# PromotedPurchaseImageAttributes

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**FileSize** | Pointer to **int32** |  | [optional] 
**FileName** | Pointer to **string** |  | [optional] 
**SourceFileChecksum** | Pointer to **string** |  | [optional] 
**AssetToken** | Pointer to **string** |  | [optional] 
**ImageAsset** | Pointer to [**ImageAsset**](ImageAsset.md) |  | [optional] 
**AssetType** | Pointer to **string** |  | [optional] 
**UploadOperations** | Pointer to [**[]UploadOperation**](UploadOperation.md) |  | [optional] 
**State** | Pointer to **string** |  | [optional] 

## Methods

### NewPromotedPurchaseImageAttributes

`func NewPromotedPurchaseImageAttributes() *PromotedPurchaseImageAttributes`

NewPromotedPurchaseImageAttributes instantiates a new PromotedPurchaseImageAttributes object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewPromotedPurchaseImageAttributesWithDefaults

`func NewPromotedPurchaseImageAttributesWithDefaults() *PromotedPurchaseImageAttributes`

NewPromotedPurchaseImageAttributesWithDefaults instantiates a new PromotedPurchaseImageAttributes object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetFileSize

`func (o *PromotedPurchaseImageAttributes) GetFileSize() int32`

GetFileSize returns the FileSize field if non-nil, zero value otherwise.

### GetFileSizeOk

`func (o *PromotedPurchaseImageAttributes) GetFileSizeOk() (*int32, bool)`

GetFileSizeOk returns a tuple with the FileSize field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFileSize

`func (o *PromotedPurchaseImageAttributes) SetFileSize(v int32)`

SetFileSize sets FileSize field to given value.

### HasFileSize

`func (o *PromotedPurchaseImageAttributes) HasFileSize() bool`

HasFileSize returns a boolean if a field has been set.

### GetFileName

`func (o *PromotedPurchaseImageAttributes) GetFileName() string`

GetFileName returns the FileName field if non-nil, zero value otherwise.

### GetFileNameOk

`func (o *PromotedPurchaseImageAttributes) GetFileNameOk() (*string, bool)`

GetFileNameOk returns a tuple with the FileName field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFileName

`func (o *PromotedPurchaseImageAttributes) SetFileName(v string)`

SetFileName sets FileName field to given value.

### HasFileName

`func (o *PromotedPurchaseImageAttributes) HasFileName() bool`

HasFileName returns a boolean if a field has been set.

### GetSourceFileChecksum

`func (o *PromotedPurchaseImageAttributes) GetSourceFileChecksum() string`

GetSourceFileChecksum returns the SourceFileChecksum field if non-nil, zero value otherwise.

### GetSourceFileChecksumOk

`func (o *PromotedPurchaseImageAttributes) GetSourceFileChecksumOk() (*string, bool)`

GetSourceFileChecksumOk returns a tuple with the SourceFileChecksum field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSourceFileChecksum

`func (o *PromotedPurchaseImageAttributes) SetSourceFileChecksum(v string)`

SetSourceFileChecksum sets SourceFileChecksum field to given value.

### HasSourceFileChecksum

`func (o *PromotedPurchaseImageAttributes) HasSourceFileChecksum() bool`

HasSourceFileChecksum returns a boolean if a field has been set.

### GetAssetToken

`func (o *PromotedPurchaseImageAttributes) GetAssetToken() string`

GetAssetToken returns the AssetToken field if non-nil, zero value otherwise.

### GetAssetTokenOk

`func (o *PromotedPurchaseImageAttributes) GetAssetTokenOk() (*string, bool)`

GetAssetTokenOk returns a tuple with the AssetToken field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAssetToken

`func (o *PromotedPurchaseImageAttributes) SetAssetToken(v string)`

SetAssetToken sets AssetToken field to given value.

### HasAssetToken

`func (o *PromotedPurchaseImageAttributes) HasAssetToken() bool`

HasAssetToken returns a boolean if a field has been set.

### GetImageAsset

`func (o *PromotedPurchaseImageAttributes) GetImageAsset() ImageAsset`

GetImageAsset returns the ImageAsset field if non-nil, zero value otherwise.

### GetImageAssetOk

`func (o *PromotedPurchaseImageAttributes) GetImageAssetOk() (*ImageAsset, bool)`

GetImageAssetOk returns a tuple with the ImageAsset field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetImageAsset

`func (o *PromotedPurchaseImageAttributes) SetImageAsset(v ImageAsset)`

SetImageAsset sets ImageAsset field to given value.

### HasImageAsset

`func (o *PromotedPurchaseImageAttributes) HasImageAsset() bool`

HasImageAsset returns a boolean if a field has been set.

### GetAssetType

`func (o *PromotedPurchaseImageAttributes) GetAssetType() string`

GetAssetType returns the AssetType field if non-nil, zero value otherwise.

### GetAssetTypeOk

`func (o *PromotedPurchaseImageAttributes) GetAssetTypeOk() (*string, bool)`

GetAssetTypeOk returns a tuple with the AssetType field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAssetType

`func (o *PromotedPurchaseImageAttributes) SetAssetType(v string)`

SetAssetType sets AssetType field to given value.

### HasAssetType

`func (o *PromotedPurchaseImageAttributes) HasAssetType() bool`

HasAssetType returns a boolean if a field has been set.

### GetUploadOperations

`func (o *PromotedPurchaseImageAttributes) GetUploadOperations() []UploadOperation`

GetUploadOperations returns the UploadOperations field if non-nil, zero value otherwise.

### GetUploadOperationsOk

`func (o *PromotedPurchaseImageAttributes) GetUploadOperationsOk() (*[]UploadOperation, bool)`

GetUploadOperationsOk returns a tuple with the UploadOperations field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetUploadOperations

`func (o *PromotedPurchaseImageAttributes) SetUploadOperations(v []UploadOperation)`

SetUploadOperations sets UploadOperations field to given value.

### HasUploadOperations

`func (o *PromotedPurchaseImageAttributes) HasUploadOperations() bool`

HasUploadOperations returns a boolean if a field has been set.

### GetState

`func (o *PromotedPurchaseImageAttributes) GetState() string`

GetState returns the State field if non-nil, zero value otherwise.

### GetStateOk

`func (o *PromotedPurchaseImageAttributes) GetStateOk() (*string, bool)`

GetStateOk returns a tuple with the State field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetState

`func (o *PromotedPurchaseImageAttributes) SetState(v string)`

SetState sets State field to given value.

### HasState

`func (o *PromotedPurchaseImageAttributes) HasState() bool`

HasState returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


