# ScmRepositoryAttributes

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**LastAccessedDate** | Pointer to **time.Time** |  | [optional] 
**HttpCloneUrl** | Pointer to **string** |  | [optional] 
**SshCloneUrl** | Pointer to **string** |  | [optional] 
**OwnerName** | Pointer to **string** |  | [optional] 
**RepositoryName** | Pointer to **string** |  | [optional] 

## Methods

### NewScmRepositoryAttributes

`func NewScmRepositoryAttributes() *ScmRepositoryAttributes`

NewScmRepositoryAttributes instantiates a new ScmRepositoryAttributes object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewScmRepositoryAttributesWithDefaults

`func NewScmRepositoryAttributesWithDefaults() *ScmRepositoryAttributes`

NewScmRepositoryAttributesWithDefaults instantiates a new ScmRepositoryAttributes object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetLastAccessedDate

`func (o *ScmRepositoryAttributes) GetLastAccessedDate() time.Time`

GetLastAccessedDate returns the LastAccessedDate field if non-nil, zero value otherwise.

### GetLastAccessedDateOk

`func (o *ScmRepositoryAttributes) GetLastAccessedDateOk() (*time.Time, bool)`

GetLastAccessedDateOk returns a tuple with the LastAccessedDate field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLastAccessedDate

`func (o *ScmRepositoryAttributes) SetLastAccessedDate(v time.Time)`

SetLastAccessedDate sets LastAccessedDate field to given value.

### HasLastAccessedDate

`func (o *ScmRepositoryAttributes) HasLastAccessedDate() bool`

HasLastAccessedDate returns a boolean if a field has been set.

### GetHttpCloneUrl

`func (o *ScmRepositoryAttributes) GetHttpCloneUrl() string`

GetHttpCloneUrl returns the HttpCloneUrl field if non-nil, zero value otherwise.

### GetHttpCloneUrlOk

`func (o *ScmRepositoryAttributes) GetHttpCloneUrlOk() (*string, bool)`

GetHttpCloneUrlOk returns a tuple with the HttpCloneUrl field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetHttpCloneUrl

`func (o *ScmRepositoryAttributes) SetHttpCloneUrl(v string)`

SetHttpCloneUrl sets HttpCloneUrl field to given value.

### HasHttpCloneUrl

`func (o *ScmRepositoryAttributes) HasHttpCloneUrl() bool`

HasHttpCloneUrl returns a boolean if a field has been set.

### GetSshCloneUrl

`func (o *ScmRepositoryAttributes) GetSshCloneUrl() string`

GetSshCloneUrl returns the SshCloneUrl field if non-nil, zero value otherwise.

### GetSshCloneUrlOk

`func (o *ScmRepositoryAttributes) GetSshCloneUrlOk() (*string, bool)`

GetSshCloneUrlOk returns a tuple with the SshCloneUrl field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSshCloneUrl

`func (o *ScmRepositoryAttributes) SetSshCloneUrl(v string)`

SetSshCloneUrl sets SshCloneUrl field to given value.

### HasSshCloneUrl

`func (o *ScmRepositoryAttributes) HasSshCloneUrl() bool`

HasSshCloneUrl returns a boolean if a field has been set.

### GetOwnerName

`func (o *ScmRepositoryAttributes) GetOwnerName() string`

GetOwnerName returns the OwnerName field if non-nil, zero value otherwise.

### GetOwnerNameOk

`func (o *ScmRepositoryAttributes) GetOwnerNameOk() (*string, bool)`

GetOwnerNameOk returns a tuple with the OwnerName field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetOwnerName

`func (o *ScmRepositoryAttributes) SetOwnerName(v string)`

SetOwnerName sets OwnerName field to given value.

### HasOwnerName

`func (o *ScmRepositoryAttributes) HasOwnerName() bool`

HasOwnerName returns a boolean if a field has been set.

### GetRepositoryName

`func (o *ScmRepositoryAttributes) GetRepositoryName() string`

GetRepositoryName returns the RepositoryName field if non-nil, zero value otherwise.

### GetRepositoryNameOk

`func (o *ScmRepositoryAttributes) GetRepositoryNameOk() (*string, bool)`

GetRepositoryNameOk returns a tuple with the RepositoryName field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRepositoryName

`func (o *ScmRepositoryAttributes) SetRepositoryName(v string)`

SetRepositoryName sets RepositoryName field to given value.

### HasRepositoryName

`func (o *ScmRepositoryAttributes) HasRepositoryName() bool`

HasRepositoryName returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


