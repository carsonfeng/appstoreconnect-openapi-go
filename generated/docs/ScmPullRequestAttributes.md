# ScmPullRequestAttributes

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Title** | Pointer to **string** |  | [optional] 
**Number** | Pointer to **int32** |  | [optional] 
**WebUrl** | Pointer to **string** |  | [optional] 
**SourceRepositoryOwner** | Pointer to **string** |  | [optional] 
**SourceRepositoryName** | Pointer to **string** |  | [optional] 
**SourceBranchName** | Pointer to **string** |  | [optional] 
**DestinationRepositoryOwner** | Pointer to **string** |  | [optional] 
**DestinationRepositoryName** | Pointer to **string** |  | [optional] 
**DestinationBranchName** | Pointer to **string** |  | [optional] 
**IsClosed** | Pointer to **bool** |  | [optional] 
**IsCrossRepository** | Pointer to **bool** |  | [optional] 

## Methods

### NewScmPullRequestAttributes

`func NewScmPullRequestAttributes() *ScmPullRequestAttributes`

NewScmPullRequestAttributes instantiates a new ScmPullRequestAttributes object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewScmPullRequestAttributesWithDefaults

`func NewScmPullRequestAttributesWithDefaults() *ScmPullRequestAttributes`

NewScmPullRequestAttributesWithDefaults instantiates a new ScmPullRequestAttributes object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetTitle

`func (o *ScmPullRequestAttributes) GetTitle() string`

GetTitle returns the Title field if non-nil, zero value otherwise.

### GetTitleOk

`func (o *ScmPullRequestAttributes) GetTitleOk() (*string, bool)`

GetTitleOk returns a tuple with the Title field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetTitle

`func (o *ScmPullRequestAttributes) SetTitle(v string)`

SetTitle sets Title field to given value.

### HasTitle

`func (o *ScmPullRequestAttributes) HasTitle() bool`

HasTitle returns a boolean if a field has been set.

### GetNumber

`func (o *ScmPullRequestAttributes) GetNumber() int32`

GetNumber returns the Number field if non-nil, zero value otherwise.

### GetNumberOk

`func (o *ScmPullRequestAttributes) GetNumberOk() (*int32, bool)`

GetNumberOk returns a tuple with the Number field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetNumber

`func (o *ScmPullRequestAttributes) SetNumber(v int32)`

SetNumber sets Number field to given value.

### HasNumber

`func (o *ScmPullRequestAttributes) HasNumber() bool`

HasNumber returns a boolean if a field has been set.

### GetWebUrl

`func (o *ScmPullRequestAttributes) GetWebUrl() string`

GetWebUrl returns the WebUrl field if non-nil, zero value otherwise.

### GetWebUrlOk

`func (o *ScmPullRequestAttributes) GetWebUrlOk() (*string, bool)`

GetWebUrlOk returns a tuple with the WebUrl field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetWebUrl

`func (o *ScmPullRequestAttributes) SetWebUrl(v string)`

SetWebUrl sets WebUrl field to given value.

### HasWebUrl

`func (o *ScmPullRequestAttributes) HasWebUrl() bool`

HasWebUrl returns a boolean if a field has been set.

### GetSourceRepositoryOwner

`func (o *ScmPullRequestAttributes) GetSourceRepositoryOwner() string`

GetSourceRepositoryOwner returns the SourceRepositoryOwner field if non-nil, zero value otherwise.

### GetSourceRepositoryOwnerOk

`func (o *ScmPullRequestAttributes) GetSourceRepositoryOwnerOk() (*string, bool)`

GetSourceRepositoryOwnerOk returns a tuple with the SourceRepositoryOwner field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSourceRepositoryOwner

`func (o *ScmPullRequestAttributes) SetSourceRepositoryOwner(v string)`

SetSourceRepositoryOwner sets SourceRepositoryOwner field to given value.

### HasSourceRepositoryOwner

`func (o *ScmPullRequestAttributes) HasSourceRepositoryOwner() bool`

HasSourceRepositoryOwner returns a boolean if a field has been set.

### GetSourceRepositoryName

`func (o *ScmPullRequestAttributes) GetSourceRepositoryName() string`

GetSourceRepositoryName returns the SourceRepositoryName field if non-nil, zero value otherwise.

### GetSourceRepositoryNameOk

`func (o *ScmPullRequestAttributes) GetSourceRepositoryNameOk() (*string, bool)`

GetSourceRepositoryNameOk returns a tuple with the SourceRepositoryName field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSourceRepositoryName

`func (o *ScmPullRequestAttributes) SetSourceRepositoryName(v string)`

SetSourceRepositoryName sets SourceRepositoryName field to given value.

### HasSourceRepositoryName

`func (o *ScmPullRequestAttributes) HasSourceRepositoryName() bool`

HasSourceRepositoryName returns a boolean if a field has been set.

### GetSourceBranchName

`func (o *ScmPullRequestAttributes) GetSourceBranchName() string`

GetSourceBranchName returns the SourceBranchName field if non-nil, zero value otherwise.

### GetSourceBranchNameOk

`func (o *ScmPullRequestAttributes) GetSourceBranchNameOk() (*string, bool)`

GetSourceBranchNameOk returns a tuple with the SourceBranchName field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSourceBranchName

`func (o *ScmPullRequestAttributes) SetSourceBranchName(v string)`

SetSourceBranchName sets SourceBranchName field to given value.

### HasSourceBranchName

`func (o *ScmPullRequestAttributes) HasSourceBranchName() bool`

HasSourceBranchName returns a boolean if a field has been set.

### GetDestinationRepositoryOwner

`func (o *ScmPullRequestAttributes) GetDestinationRepositoryOwner() string`

GetDestinationRepositoryOwner returns the DestinationRepositoryOwner field if non-nil, zero value otherwise.

### GetDestinationRepositoryOwnerOk

`func (o *ScmPullRequestAttributes) GetDestinationRepositoryOwnerOk() (*string, bool)`

GetDestinationRepositoryOwnerOk returns a tuple with the DestinationRepositoryOwner field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDestinationRepositoryOwner

`func (o *ScmPullRequestAttributes) SetDestinationRepositoryOwner(v string)`

SetDestinationRepositoryOwner sets DestinationRepositoryOwner field to given value.

### HasDestinationRepositoryOwner

`func (o *ScmPullRequestAttributes) HasDestinationRepositoryOwner() bool`

HasDestinationRepositoryOwner returns a boolean if a field has been set.

### GetDestinationRepositoryName

`func (o *ScmPullRequestAttributes) GetDestinationRepositoryName() string`

GetDestinationRepositoryName returns the DestinationRepositoryName field if non-nil, zero value otherwise.

### GetDestinationRepositoryNameOk

`func (o *ScmPullRequestAttributes) GetDestinationRepositoryNameOk() (*string, bool)`

GetDestinationRepositoryNameOk returns a tuple with the DestinationRepositoryName field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDestinationRepositoryName

`func (o *ScmPullRequestAttributes) SetDestinationRepositoryName(v string)`

SetDestinationRepositoryName sets DestinationRepositoryName field to given value.

### HasDestinationRepositoryName

`func (o *ScmPullRequestAttributes) HasDestinationRepositoryName() bool`

HasDestinationRepositoryName returns a boolean if a field has been set.

### GetDestinationBranchName

`func (o *ScmPullRequestAttributes) GetDestinationBranchName() string`

GetDestinationBranchName returns the DestinationBranchName field if non-nil, zero value otherwise.

### GetDestinationBranchNameOk

`func (o *ScmPullRequestAttributes) GetDestinationBranchNameOk() (*string, bool)`

GetDestinationBranchNameOk returns a tuple with the DestinationBranchName field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDestinationBranchName

`func (o *ScmPullRequestAttributes) SetDestinationBranchName(v string)`

SetDestinationBranchName sets DestinationBranchName field to given value.

### HasDestinationBranchName

`func (o *ScmPullRequestAttributes) HasDestinationBranchName() bool`

HasDestinationBranchName returns a boolean if a field has been set.

### GetIsClosed

`func (o *ScmPullRequestAttributes) GetIsClosed() bool`

GetIsClosed returns the IsClosed field if non-nil, zero value otherwise.

### GetIsClosedOk

`func (o *ScmPullRequestAttributes) GetIsClosedOk() (*bool, bool)`

GetIsClosedOk returns a tuple with the IsClosed field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIsClosed

`func (o *ScmPullRequestAttributes) SetIsClosed(v bool)`

SetIsClosed sets IsClosed field to given value.

### HasIsClosed

`func (o *ScmPullRequestAttributes) HasIsClosed() bool`

HasIsClosed returns a boolean if a field has been set.

### GetIsCrossRepository

`func (o *ScmPullRequestAttributes) GetIsCrossRepository() bool`

GetIsCrossRepository returns the IsCrossRepository field if non-nil, zero value otherwise.

### GetIsCrossRepositoryOk

`func (o *ScmPullRequestAttributes) GetIsCrossRepositoryOk() (*bool, bool)`

GetIsCrossRepositoryOk returns a tuple with the IsCrossRepository field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIsCrossRepository

`func (o *ScmPullRequestAttributes) SetIsCrossRepository(v bool)`

SetIsCrossRepository sets IsCrossRepository field to given value.

### HasIsCrossRepository

`func (o *ScmPullRequestAttributes) HasIsCrossRepository() bool`

HasIsCrossRepository returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


