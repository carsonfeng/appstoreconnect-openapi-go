# ScmRepositoryResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**ScmRepository**](ScmRepository.md) |  | 
**Included** | Pointer to [**[]ScmRepositoriesResponseIncludedInner**](ScmRepositoriesResponseIncludedInner.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewScmRepositoryResponse

`func NewScmRepositoryResponse(data ScmRepository, links DocumentLinks, ) *ScmRepositoryResponse`

NewScmRepositoryResponse instantiates a new ScmRepositoryResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewScmRepositoryResponseWithDefaults

`func NewScmRepositoryResponseWithDefaults() *ScmRepositoryResponse`

NewScmRepositoryResponseWithDefaults instantiates a new ScmRepositoryResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *ScmRepositoryResponse) GetData() ScmRepository`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *ScmRepositoryResponse) GetDataOk() (*ScmRepository, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *ScmRepositoryResponse) SetData(v ScmRepository)`

SetData sets Data field to given value.


### GetIncluded

`func (o *ScmRepositoryResponse) GetIncluded() []ScmRepositoriesResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *ScmRepositoryResponse) GetIncludedOk() (*[]ScmRepositoriesResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *ScmRepositoryResponse) SetIncluded(v []ScmRepositoriesResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *ScmRepositoryResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *ScmRepositoryResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *ScmRepositoryResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *ScmRepositoryResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


