# ScmRepositoriesResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**[]ScmRepository**](ScmRepository.md) |  | 
**Included** | Pointer to [**[]ScmRepositoriesResponseIncludedInner**](ScmRepositoriesResponseIncludedInner.md) |  | [optional] 
**Links** | [**PagedDocumentLinks**](PagedDocumentLinks.md) |  | 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 

## Methods

### NewScmRepositoriesResponse

`func NewScmRepositoriesResponse(data []ScmRepository, links PagedDocumentLinks, ) *ScmRepositoriesResponse`

NewScmRepositoriesResponse instantiates a new ScmRepositoriesResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewScmRepositoriesResponseWithDefaults

`func NewScmRepositoriesResponseWithDefaults() *ScmRepositoriesResponse`

NewScmRepositoriesResponseWithDefaults instantiates a new ScmRepositoriesResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *ScmRepositoriesResponse) GetData() []ScmRepository`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *ScmRepositoriesResponse) GetDataOk() (*[]ScmRepository, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *ScmRepositoriesResponse) SetData(v []ScmRepository)`

SetData sets Data field to given value.


### GetIncluded

`func (o *ScmRepositoriesResponse) GetIncluded() []ScmRepositoriesResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *ScmRepositoriesResponse) GetIncludedOk() (*[]ScmRepositoriesResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *ScmRepositoriesResponse) SetIncluded(v []ScmRepositoriesResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *ScmRepositoriesResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *ScmRepositoriesResponse) GetLinks() PagedDocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *ScmRepositoriesResponse) GetLinksOk() (*PagedDocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *ScmRepositoriesResponse) SetLinks(v PagedDocumentLinks)`

SetLinks sets Links field to given value.


### GetMeta

`func (o *ScmRepositoriesResponse) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *ScmRepositoriesResponse) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *ScmRepositoriesResponse) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *ScmRepositoriesResponse) HasMeta() bool`

HasMeta returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


