# CiBuildRunsResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**[]CiBuildRun**](CiBuildRun.md) |  | 
**Included** | Pointer to [**[]CiBuildRunsResponseIncludedInner**](CiBuildRunsResponseIncludedInner.md) |  | [optional] 
**Links** | [**PagedDocumentLinks**](PagedDocumentLinks.md) |  | 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 

## Methods

### NewCiBuildRunsResponse

`func NewCiBuildRunsResponse(data []CiBuildRun, links PagedDocumentLinks, ) *CiBuildRunsResponse`

NewCiBuildRunsResponse instantiates a new CiBuildRunsResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCiBuildRunsResponseWithDefaults

`func NewCiBuildRunsResponseWithDefaults() *CiBuildRunsResponse`

NewCiBuildRunsResponseWithDefaults instantiates a new CiBuildRunsResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *CiBuildRunsResponse) GetData() []CiBuildRun`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *CiBuildRunsResponse) GetDataOk() (*[]CiBuildRun, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *CiBuildRunsResponse) SetData(v []CiBuildRun)`

SetData sets Data field to given value.


### GetIncluded

`func (o *CiBuildRunsResponse) GetIncluded() []CiBuildRunsResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *CiBuildRunsResponse) GetIncludedOk() (*[]CiBuildRunsResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *CiBuildRunsResponse) SetIncluded(v []CiBuildRunsResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *CiBuildRunsResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *CiBuildRunsResponse) GetLinks() PagedDocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *CiBuildRunsResponse) GetLinksOk() (*PagedDocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *CiBuildRunsResponse) SetLinks(v PagedDocumentLinks)`

SetLinks sets Links field to given value.


### GetMeta

`func (o *CiBuildRunsResponse) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *CiBuildRunsResponse) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *CiBuildRunsResponse) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *CiBuildRunsResponse) HasMeta() bool`

HasMeta returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


