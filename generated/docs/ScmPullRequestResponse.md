# ScmPullRequestResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**ScmPullRequest**](ScmPullRequest.md) |  | 
**Included** | Pointer to [**[]ScmRepository**](ScmRepository.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewScmPullRequestResponse

`func NewScmPullRequestResponse(data ScmPullRequest, links DocumentLinks, ) *ScmPullRequestResponse`

NewScmPullRequestResponse instantiates a new ScmPullRequestResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewScmPullRequestResponseWithDefaults

`func NewScmPullRequestResponseWithDefaults() *ScmPullRequestResponse`

NewScmPullRequestResponseWithDefaults instantiates a new ScmPullRequestResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *ScmPullRequestResponse) GetData() ScmPullRequest`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *ScmPullRequestResponse) GetDataOk() (*ScmPullRequest, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *ScmPullRequestResponse) SetData(v ScmPullRequest)`

SetData sets Data field to given value.


### GetIncluded

`func (o *ScmPullRequestResponse) GetIncluded() []ScmRepository`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *ScmPullRequestResponse) GetIncludedOk() (*[]ScmRepository, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *ScmPullRequestResponse) SetIncluded(v []ScmRepository)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *ScmPullRequestResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *ScmPullRequestResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *ScmPullRequestResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *ScmPullRequestResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


