# CiIssueAttributes

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**IssueType** | Pointer to **string** |  | [optional] 
**Message** | Pointer to **string** |  | [optional] 
**FileSource** | Pointer to [**FileLocation**](FileLocation.md) |  | [optional] 
**Category** | Pointer to **string** |  | [optional] 

## Methods

### NewCiIssueAttributes

`func NewCiIssueAttributes() *CiIssueAttributes`

NewCiIssueAttributes instantiates a new CiIssueAttributes object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCiIssueAttributesWithDefaults

`func NewCiIssueAttributesWithDefaults() *CiIssueAttributes`

NewCiIssueAttributesWithDefaults instantiates a new CiIssueAttributes object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetIssueType

`func (o *CiIssueAttributes) GetIssueType() string`

GetIssueType returns the IssueType field if non-nil, zero value otherwise.

### GetIssueTypeOk

`func (o *CiIssueAttributes) GetIssueTypeOk() (*string, bool)`

GetIssueTypeOk returns a tuple with the IssueType field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIssueType

`func (o *CiIssueAttributes) SetIssueType(v string)`

SetIssueType sets IssueType field to given value.

### HasIssueType

`func (o *CiIssueAttributes) HasIssueType() bool`

HasIssueType returns a boolean if a field has been set.

### GetMessage

`func (o *CiIssueAttributes) GetMessage() string`

GetMessage returns the Message field if non-nil, zero value otherwise.

### GetMessageOk

`func (o *CiIssueAttributes) GetMessageOk() (*string, bool)`

GetMessageOk returns a tuple with the Message field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMessage

`func (o *CiIssueAttributes) SetMessage(v string)`

SetMessage sets Message field to given value.

### HasMessage

`func (o *CiIssueAttributes) HasMessage() bool`

HasMessage returns a boolean if a field has been set.

### GetFileSource

`func (o *CiIssueAttributes) GetFileSource() FileLocation`

GetFileSource returns the FileSource field if non-nil, zero value otherwise.

### GetFileSourceOk

`func (o *CiIssueAttributes) GetFileSourceOk() (*FileLocation, bool)`

GetFileSourceOk returns a tuple with the FileSource field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetFileSource

`func (o *CiIssueAttributes) SetFileSource(v FileLocation)`

SetFileSource sets FileSource field to given value.

### HasFileSource

`func (o *CiIssueAttributes) HasFileSource() bool`

HasFileSource returns a boolean if a field has been set.

### GetCategory

`func (o *CiIssueAttributes) GetCategory() string`

GetCategory returns the Category field if non-nil, zero value otherwise.

### GetCategoryOk

`func (o *CiIssueAttributes) GetCategoryOk() (*string, bool)`

GetCategoryOk returns a tuple with the Category field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCategory

`func (o *CiIssueAttributes) SetCategory(v string)`

SetCategory sets Category field to given value.

### HasCategory

`func (o *CiIssueAttributes) HasCategory() bool`

HasCategory returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


