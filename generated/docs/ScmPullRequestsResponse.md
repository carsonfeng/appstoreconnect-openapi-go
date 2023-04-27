# ScmPullRequestsResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**[]ScmPullRequest**](ScmPullRequest.md) |  | 
**Included** | Pointer to [**[]ScmRepository**](ScmRepository.md) |  | [optional] 
**Links** | [**PagedDocumentLinks**](PagedDocumentLinks.md) |  | 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 

## Methods

### NewScmPullRequestsResponse

`func NewScmPullRequestsResponse(data []ScmPullRequest, links PagedDocumentLinks, ) *ScmPullRequestsResponse`

NewScmPullRequestsResponse instantiates a new ScmPullRequestsResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewScmPullRequestsResponseWithDefaults

`func NewScmPullRequestsResponseWithDefaults() *ScmPullRequestsResponse`

NewScmPullRequestsResponseWithDefaults instantiates a new ScmPullRequestsResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *ScmPullRequestsResponse) GetData() []ScmPullRequest`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *ScmPullRequestsResponse) GetDataOk() (*[]ScmPullRequest, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *ScmPullRequestsResponse) SetData(v []ScmPullRequest)`

SetData sets Data field to given value.


### GetIncluded

`func (o *ScmPullRequestsResponse) GetIncluded() []ScmRepository`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *ScmPullRequestsResponse) GetIncludedOk() (*[]ScmRepository, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *ScmPullRequestsResponse) SetIncluded(v []ScmRepository)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *ScmPullRequestsResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *ScmPullRequestsResponse) GetLinks() PagedDocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *ScmPullRequestsResponse) GetLinksOk() (*PagedDocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *ScmPullRequestsResponse) SetLinks(v PagedDocumentLinks)`

SetLinks sets Links field to given value.


### GetMeta

`func (o *ScmPullRequestsResponse) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *ScmPullRequestsResponse) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *ScmPullRequestsResponse) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *ScmPullRequestsResponse) HasMeta() bool`

HasMeta returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


