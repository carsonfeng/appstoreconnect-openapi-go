# CiWorkflowsResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**[]CiWorkflow**](CiWorkflow.md) |  | 
**Included** | Pointer to [**[]CiWorkflowsResponseIncludedInner**](CiWorkflowsResponseIncludedInner.md) |  | [optional] 
**Links** | [**PagedDocumentLinks**](PagedDocumentLinks.md) |  | 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 

## Methods

### NewCiWorkflowsResponse

`func NewCiWorkflowsResponse(data []CiWorkflow, links PagedDocumentLinks, ) *CiWorkflowsResponse`

NewCiWorkflowsResponse instantiates a new CiWorkflowsResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCiWorkflowsResponseWithDefaults

`func NewCiWorkflowsResponseWithDefaults() *CiWorkflowsResponse`

NewCiWorkflowsResponseWithDefaults instantiates a new CiWorkflowsResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *CiWorkflowsResponse) GetData() []CiWorkflow`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *CiWorkflowsResponse) GetDataOk() (*[]CiWorkflow, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *CiWorkflowsResponse) SetData(v []CiWorkflow)`

SetData sets Data field to given value.


### GetIncluded

`func (o *CiWorkflowsResponse) GetIncluded() []CiWorkflowsResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *CiWorkflowsResponse) GetIncludedOk() (*[]CiWorkflowsResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *CiWorkflowsResponse) SetIncluded(v []CiWorkflowsResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *CiWorkflowsResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *CiWorkflowsResponse) GetLinks() PagedDocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *CiWorkflowsResponse) GetLinksOk() (*PagedDocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *CiWorkflowsResponse) SetLinks(v PagedDocumentLinks)`

SetLinks sets Links field to given value.


### GetMeta

`func (o *CiWorkflowsResponse) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *CiWorkflowsResponse) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *CiWorkflowsResponse) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *CiWorkflowsResponse) HasMeta() bool`

HasMeta returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


