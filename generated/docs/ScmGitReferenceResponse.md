# ScmGitReferenceResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**ScmGitReference**](ScmGitReference.md) |  | 
**Included** | Pointer to [**[]ScmRepository**](ScmRepository.md) |  | [optional] 
**Links** | [**DocumentLinks**](DocumentLinks.md) |  | 

## Methods

### NewScmGitReferenceResponse

`func NewScmGitReferenceResponse(data ScmGitReference, links DocumentLinks, ) *ScmGitReferenceResponse`

NewScmGitReferenceResponse instantiates a new ScmGitReferenceResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewScmGitReferenceResponseWithDefaults

`func NewScmGitReferenceResponseWithDefaults() *ScmGitReferenceResponse`

NewScmGitReferenceResponseWithDefaults instantiates a new ScmGitReferenceResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *ScmGitReferenceResponse) GetData() ScmGitReference`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *ScmGitReferenceResponse) GetDataOk() (*ScmGitReference, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *ScmGitReferenceResponse) SetData(v ScmGitReference)`

SetData sets Data field to given value.


### GetIncluded

`func (o *ScmGitReferenceResponse) GetIncluded() []ScmRepository`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *ScmGitReferenceResponse) GetIncludedOk() (*[]ScmRepository, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *ScmGitReferenceResponse) SetIncluded(v []ScmRepository)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *ScmGitReferenceResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *ScmGitReferenceResponse) GetLinks() DocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *ScmGitReferenceResponse) GetLinksOk() (*DocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *ScmGitReferenceResponse) SetLinks(v DocumentLinks)`

SetLinks sets Links field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


