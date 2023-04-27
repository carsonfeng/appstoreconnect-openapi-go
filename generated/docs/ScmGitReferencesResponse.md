# ScmGitReferencesResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**[]ScmGitReference**](ScmGitReference.md) |  | 
**Included** | Pointer to [**[]ScmRepository**](ScmRepository.md) |  | [optional] 
**Links** | [**PagedDocumentLinks**](PagedDocumentLinks.md) |  | 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 

## Methods

### NewScmGitReferencesResponse

`func NewScmGitReferencesResponse(data []ScmGitReference, links PagedDocumentLinks, ) *ScmGitReferencesResponse`

NewScmGitReferencesResponse instantiates a new ScmGitReferencesResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewScmGitReferencesResponseWithDefaults

`func NewScmGitReferencesResponseWithDefaults() *ScmGitReferencesResponse`

NewScmGitReferencesResponseWithDefaults instantiates a new ScmGitReferencesResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *ScmGitReferencesResponse) GetData() []ScmGitReference`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *ScmGitReferencesResponse) GetDataOk() (*[]ScmGitReference, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *ScmGitReferencesResponse) SetData(v []ScmGitReference)`

SetData sets Data field to given value.


### GetIncluded

`func (o *ScmGitReferencesResponse) GetIncluded() []ScmRepository`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *ScmGitReferencesResponse) GetIncludedOk() (*[]ScmRepository, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *ScmGitReferencesResponse) SetIncluded(v []ScmRepository)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *ScmGitReferencesResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *ScmGitReferencesResponse) GetLinks() PagedDocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *ScmGitReferencesResponse) GetLinksOk() (*PagedDocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *ScmGitReferencesResponse) SetLinks(v PagedDocumentLinks)`

SetLinks sets Links field to given value.


### GetMeta

`func (o *ScmGitReferencesResponse) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *ScmGitReferencesResponse) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *ScmGitReferencesResponse) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *ScmGitReferencesResponse) HasMeta() bool`

HasMeta returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


