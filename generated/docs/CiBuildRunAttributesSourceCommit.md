# CiBuildRunAttributesSourceCommit

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**CommitSha** | Pointer to **string** |  | [optional] 
**Message** | Pointer to **string** |  | [optional] 
**Author** | Pointer to [**CiGitUser**](CiGitUser.md) |  | [optional] 
**Committer** | Pointer to [**CiGitUser**](CiGitUser.md) |  | [optional] 
**WebUrl** | Pointer to **string** |  | [optional] 

## Methods

### NewCiBuildRunAttributesSourceCommit

`func NewCiBuildRunAttributesSourceCommit() *CiBuildRunAttributesSourceCommit`

NewCiBuildRunAttributesSourceCommit instantiates a new CiBuildRunAttributesSourceCommit object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCiBuildRunAttributesSourceCommitWithDefaults

`func NewCiBuildRunAttributesSourceCommitWithDefaults() *CiBuildRunAttributesSourceCommit`

NewCiBuildRunAttributesSourceCommitWithDefaults instantiates a new CiBuildRunAttributesSourceCommit object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetCommitSha

`func (o *CiBuildRunAttributesSourceCommit) GetCommitSha() string`

GetCommitSha returns the CommitSha field if non-nil, zero value otherwise.

### GetCommitShaOk

`func (o *CiBuildRunAttributesSourceCommit) GetCommitShaOk() (*string, bool)`

GetCommitShaOk returns a tuple with the CommitSha field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCommitSha

`func (o *CiBuildRunAttributesSourceCommit) SetCommitSha(v string)`

SetCommitSha sets CommitSha field to given value.

### HasCommitSha

`func (o *CiBuildRunAttributesSourceCommit) HasCommitSha() bool`

HasCommitSha returns a boolean if a field has been set.

### GetMessage

`func (o *CiBuildRunAttributesSourceCommit) GetMessage() string`

GetMessage returns the Message field if non-nil, zero value otherwise.

### GetMessageOk

`func (o *CiBuildRunAttributesSourceCommit) GetMessageOk() (*string, bool)`

GetMessageOk returns a tuple with the Message field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMessage

`func (o *CiBuildRunAttributesSourceCommit) SetMessage(v string)`

SetMessage sets Message field to given value.

### HasMessage

`func (o *CiBuildRunAttributesSourceCommit) HasMessage() bool`

HasMessage returns a boolean if a field has been set.

### GetAuthor

`func (o *CiBuildRunAttributesSourceCommit) GetAuthor() CiGitUser`

GetAuthor returns the Author field if non-nil, zero value otherwise.

### GetAuthorOk

`func (o *CiBuildRunAttributesSourceCommit) GetAuthorOk() (*CiGitUser, bool)`

GetAuthorOk returns a tuple with the Author field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAuthor

`func (o *CiBuildRunAttributesSourceCommit) SetAuthor(v CiGitUser)`

SetAuthor sets Author field to given value.

### HasAuthor

`func (o *CiBuildRunAttributesSourceCommit) HasAuthor() bool`

HasAuthor returns a boolean if a field has been set.

### GetCommitter

`func (o *CiBuildRunAttributesSourceCommit) GetCommitter() CiGitUser`

GetCommitter returns the Committer field if non-nil, zero value otherwise.

### GetCommitterOk

`func (o *CiBuildRunAttributesSourceCommit) GetCommitterOk() (*CiGitUser, bool)`

GetCommitterOk returns a tuple with the Committer field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCommitter

`func (o *CiBuildRunAttributesSourceCommit) SetCommitter(v CiGitUser)`

SetCommitter sets Committer field to given value.

### HasCommitter

`func (o *CiBuildRunAttributesSourceCommit) HasCommitter() bool`

HasCommitter returns a boolean if a field has been set.

### GetWebUrl

`func (o *CiBuildRunAttributesSourceCommit) GetWebUrl() string`

GetWebUrl returns the WebUrl field if non-nil, zero value otherwise.

### GetWebUrlOk

`func (o *CiBuildRunAttributesSourceCommit) GetWebUrlOk() (*string, bool)`

GetWebUrlOk returns a tuple with the WebUrl field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetWebUrl

`func (o *CiBuildRunAttributesSourceCommit) SetWebUrl(v string)`

SetWebUrl sets WebUrl field to given value.

### HasWebUrl

`func (o *CiBuildRunAttributesSourceCommit) HasWebUrl() bool`

HasWebUrl returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


