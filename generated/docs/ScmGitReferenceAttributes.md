# ScmGitReferenceAttributes

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Name** | Pointer to **string** |  | [optional] 
**CanonicalName** | Pointer to **string** |  | [optional] 
**IsDeleted** | Pointer to **bool** |  | [optional] 
**Kind** | Pointer to [**CiGitRefKind**](CiGitRefKind.md) |  | [optional] 

## Methods

### NewScmGitReferenceAttributes

`func NewScmGitReferenceAttributes() *ScmGitReferenceAttributes`

NewScmGitReferenceAttributes instantiates a new ScmGitReferenceAttributes object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewScmGitReferenceAttributesWithDefaults

`func NewScmGitReferenceAttributesWithDefaults() *ScmGitReferenceAttributes`

NewScmGitReferenceAttributesWithDefaults instantiates a new ScmGitReferenceAttributes object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetName

`func (o *ScmGitReferenceAttributes) GetName() string`

GetName returns the Name field if non-nil, zero value otherwise.

### GetNameOk

`func (o *ScmGitReferenceAttributes) GetNameOk() (*string, bool)`

GetNameOk returns a tuple with the Name field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetName

`func (o *ScmGitReferenceAttributes) SetName(v string)`

SetName sets Name field to given value.

### HasName

`func (o *ScmGitReferenceAttributes) HasName() bool`

HasName returns a boolean if a field has been set.

### GetCanonicalName

`func (o *ScmGitReferenceAttributes) GetCanonicalName() string`

GetCanonicalName returns the CanonicalName field if non-nil, zero value otherwise.

### GetCanonicalNameOk

`func (o *ScmGitReferenceAttributes) GetCanonicalNameOk() (*string, bool)`

GetCanonicalNameOk returns a tuple with the CanonicalName field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetCanonicalName

`func (o *ScmGitReferenceAttributes) SetCanonicalName(v string)`

SetCanonicalName sets CanonicalName field to given value.

### HasCanonicalName

`func (o *ScmGitReferenceAttributes) HasCanonicalName() bool`

HasCanonicalName returns a boolean if a field has been set.

### GetIsDeleted

`func (o *ScmGitReferenceAttributes) GetIsDeleted() bool`

GetIsDeleted returns the IsDeleted field if non-nil, zero value otherwise.

### GetIsDeletedOk

`func (o *ScmGitReferenceAttributes) GetIsDeletedOk() (*bool, bool)`

GetIsDeletedOk returns a tuple with the IsDeleted field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIsDeleted

`func (o *ScmGitReferenceAttributes) SetIsDeleted(v bool)`

SetIsDeleted sets IsDeleted field to given value.

### HasIsDeleted

`func (o *ScmGitReferenceAttributes) HasIsDeleted() bool`

HasIsDeleted returns a boolean if a field has been set.

### GetKind

`func (o *ScmGitReferenceAttributes) GetKind() CiGitRefKind`

GetKind returns the Kind field if non-nil, zero value otherwise.

### GetKindOk

`func (o *ScmGitReferenceAttributes) GetKindOk() (*CiGitRefKind, bool)`

GetKindOk returns a tuple with the Kind field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetKind

`func (o *ScmGitReferenceAttributes) SetKind(v CiGitRefKind)`

SetKind sets Kind field to given value.

### HasKind

`func (o *ScmGitReferenceAttributes) HasKind() bool`

HasKind returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


