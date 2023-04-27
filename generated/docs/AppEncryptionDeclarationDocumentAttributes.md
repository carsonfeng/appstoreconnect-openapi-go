# AppEncryptionDeclarationDocumentAttributes

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**FileSize** | Pointer to **int32** |  | [optional] 
**FileName** | Pointer to **string** |  | [optional] 
**AssetToken** | Pointer to **string** |  | [optional] 
**DownloadUrl** | Pointer to **string** |  | [optional] 
**SourceFileChecksum** | Pointer to **string** |  | [optional] 
**UploadOperations** | Pointer to [**[]UploadOperation**](UploadOperation.md) |  | [optional] 
**AssetDeliveryState** | Pointer to [**AppMediaAssetState**](AppMediaAssetState.md) |  | [optional] 

## Methods

### NewAppEncryptionDeclarationDocumentAttributes

`func NewAppEncryptionDeclarationDocumentAttributes() *AppEncryptionDeclarationDocumentAttributes`

NewAppEncryptionDeclarationDocumentAttributes instantiates a new AppEncryptionDeclarationDocumentAttributes object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppEncryptionDeclarationDocumentAttributesWithDefaults

`func NewAppEncryptionDeclarationDocumentAttributesWithDefaults() *AppEncryptionDeclarationDocumentAttributes`

NewAppEncryptionDeclarationDocumentAttributesWithDefaults instantiates a new AppEncryptionDeclarationDocumentAttributes object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetFileSize

`func (o *AppEncryptionDeclarationDocumentAttributes) GetFileSize() int32`

GetFileSize returns the FileSize field if non-nil, zero value otherwise.

### GetFileSizeOk

`func (o *AppEncryptionDeclarationDocumentAttributes) GetFileSizeOk() (*int32, bool)`

GetFileSizeOk returns a tuple with the FileSize field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFileSize

`func (o *AppEncryptionDeclarationDocumentAttributes) SetFileSize(v int32)`

SetFileSize sets FileSize field to given value.

### HasFileSize

`func (o *AppEncryptionDeclarationDocumentAttributes) HasFileSize() bool`

HasFileSize returns a boolean if a field has been set.

### GetFileName

`func (o *AppEncryptionDeclarationDocumentAttributes) GetFileName() string`

GetFileName returns the FileName field if non-nil, zero value otherwise.

### GetFileNameOk

`func (o *AppEncryptionDeclarationDocumentAttributes) GetFileNameOk() (*string, bool)`

GetFileNameOk returns a tuple with the FileName field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFileName

`func (o *AppEncryptionDeclarationDocumentAttributes) SetFileName(v string)`

SetFileName sets FileName field to given value.

### HasFileName

`func (o *AppEncryptionDeclarationDocumentAttributes) HasFileName() bool`

HasFileName returns a boolean if a field has been set.

### GetAssetToken

`func (o *AppEncryptionDeclarationDocumentAttributes) GetAssetToken() string`

GetAssetToken returns the AssetToken field if non-nil, zero value otherwise.

### GetAssetTokenOk

`func (o *AppEncryptionDeclarationDocumentAttributes) GetAssetTokenOk() (*string, bool)`

GetAssetTokenOk returns a tuple with the AssetToken field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAssetToken

`func (o *AppEncryptionDeclarationDocumentAttributes) SetAssetToken(v string)`

SetAssetToken sets AssetToken field to given value.

### HasAssetToken

`func (o *AppEncryptionDeclarationDocumentAttributes) HasAssetToken() bool`

HasAssetToken returns a boolean if a field has been set.

### GetDownloadUrl

`func (o *AppEncryptionDeclarationDocumentAttributes) GetDownloadUrl() string`

GetDownloadUrl returns the DownloadUrl field if non-nil, zero value otherwise.

### GetDownloadUrlOk

`func (o *AppEncryptionDeclarationDocumentAttributes) GetDownloadUrlOk() (*string, bool)`

GetDownloadUrlOk returns a tuple with the DownloadUrl field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDownloadUrl

`func (o *AppEncryptionDeclarationDocumentAttributes) SetDownloadUrl(v string)`

SetDownloadUrl sets DownloadUrl field to given value.

### HasDownloadUrl

`func (o *AppEncryptionDeclarationDocumentAttributes) HasDownloadUrl() bool`

HasDownloadUrl returns a boolean if a field has been set.

### GetSourceFileChecksum

`func (o *AppEncryptionDeclarationDocumentAttributes) GetSourceFileChecksum() string`

GetSourceFileChecksum returns the SourceFileChecksum field if non-nil, zero value otherwise.

### GetSourceFileChecksumOk

`func (o *AppEncryptionDeclarationDocumentAttributes) GetSourceFileChecksumOk() (*string, bool)`

GetSourceFileChecksumOk returns a tuple with the SourceFileChecksum field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSourceFileChecksum

`func (o *AppEncryptionDeclarationDocumentAttributes) SetSourceFileChecksum(v string)`

SetSourceFileChecksum sets SourceFileChecksum field to given value.

### HasSourceFileChecksum

`func (o *AppEncryptionDeclarationDocumentAttributes) HasSourceFileChecksum() bool`

HasSourceFileChecksum returns a boolean if a field has been set.

### GetUploadOperations

`func (o *AppEncryptionDeclarationDocumentAttributes) GetUploadOperations() []UploadOperation`

GetUploadOperations returns the UploadOperations field if non-nil, zero value otherwise.

### GetUploadOperationsOk

`func (o *AppEncryptionDeclarationDocumentAttributes) GetUploadOperationsOk() (*[]UploadOperation, bool)`

GetUploadOperationsOk returns a tuple with the UploadOperations field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetUploadOperations

`func (o *AppEncryptionDeclarationDocumentAttributes) SetUploadOperations(v []UploadOperation)`

SetUploadOperations sets UploadOperations field to given value.

### HasUploadOperations

`func (o *AppEncryptionDeclarationDocumentAttributes) HasUploadOperations() bool`

HasUploadOperations returns a boolean if a field has been set.

### GetAssetDeliveryState

`func (o *AppEncryptionDeclarationDocumentAttributes) GetAssetDeliveryState() AppMediaAssetState`

GetAssetDeliveryState returns the AssetDeliveryState field if non-nil, zero value otherwise.

### GetAssetDeliveryStateOk

`func (o *AppEncryptionDeclarationDocumentAttributes) GetAssetDeliveryStateOk() (*AppMediaAssetState, bool)`

GetAssetDeliveryStateOk returns a tuple with the AssetDeliveryState field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAssetDeliveryState

`func (o *AppEncryptionDeclarationDocumentAttributes) SetAssetDeliveryState(v AppMediaAssetState)`

SetAssetDeliveryState sets AssetDeliveryState field to given value.

### HasAssetDeliveryState

`func (o *AppEncryptionDeclarationDocumentAttributes) HasAssetDeliveryState() bool`

HasAssetDeliveryState returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


