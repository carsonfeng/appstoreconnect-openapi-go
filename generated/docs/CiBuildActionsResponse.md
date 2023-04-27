# CiBuildActionsResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**[]CiBuildAction**](CiBuildAction.md) |  | 
**Included** | Pointer to [**[]CiBuildRun**](CiBuildRun.md) |  | [optional] 
**Links** | [**PagedDocumentLinks**](PagedDocumentLinks.md) |  | 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 

## Methods

### NewCiBuildActionsResponse

`func NewCiBuildActionsResponse(data []CiBuildAction, links PagedDocumentLinks, ) *CiBuildActionsResponse`

NewCiBuildActionsResponse instantiates a new CiBuildActionsResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCiBuildActionsResponseWithDefaults

`func NewCiBuildActionsResponseWithDefaults() *CiBuildActionsResponse`

NewCiBuildActionsResponseWithDefaults instantiates a new CiBuildActionsResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *CiBuildActionsResponse) GetData() []CiBuildAction`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *CiBuildActionsResponse) GetDataOk() (*[]CiBuildAction, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *CiBuildActionsResponse) SetData(v []CiBuildAction)`

SetData sets Data field to given value.


### GetIncluded

`func (o *CiBuildActionsResponse) GetIncluded() []CiBuildRun`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *CiBuildActionsResponse) GetIncludedOk() (*[]CiBuildRun, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *CiBuildActionsResponse) SetIncluded(v []CiBuildRun)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *CiBuildActionsResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *CiBuildActionsResponse) GetLinks() PagedDocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *CiBuildActionsResponse) GetLinksOk() (*PagedDocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *CiBuildActionsResponse) SetLinks(v PagedDocumentLinks)`

SetLinks sets Links field to given value.


### GetMeta

`func (o *CiBuildActionsResponse) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *CiBuildActionsResponse) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *CiBuildActionsResponse) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *CiBuildActionsResponse) HasMeta() bool`

HasMeta returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


