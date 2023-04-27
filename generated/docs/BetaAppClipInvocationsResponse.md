# BetaAppClipInvocationsResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**[]BetaAppClipInvocation**](BetaAppClipInvocation.md) |  | 
**Included** | Pointer to [**[]BetaAppClipInvocationLocalization**](BetaAppClipInvocationLocalization.md) |  | [optional] 
**Links** | [**PagedDocumentLinks**](PagedDocumentLinks.md) |  | 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 

## Methods

### NewBetaAppClipInvocationsResponse

`func NewBetaAppClipInvocationsResponse(data []BetaAppClipInvocation, links PagedDocumentLinks, ) *BetaAppClipInvocationsResponse`

NewBetaAppClipInvocationsResponse instantiates a new BetaAppClipInvocationsResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewBetaAppClipInvocationsResponseWithDefaults

`func NewBetaAppClipInvocationsResponseWithDefaults() *BetaAppClipInvocationsResponse`

NewBetaAppClipInvocationsResponseWithDefaults instantiates a new BetaAppClipInvocationsResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *BetaAppClipInvocationsResponse) GetData() []BetaAppClipInvocation`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *BetaAppClipInvocationsResponse) GetDataOk() (*[]BetaAppClipInvocation, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *BetaAppClipInvocationsResponse) SetData(v []BetaAppClipInvocation)`

SetData sets Data field to given value.


### GetIncluded

`func (o *BetaAppClipInvocationsResponse) GetIncluded() []BetaAppClipInvocationLocalization`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *BetaAppClipInvocationsResponse) GetIncludedOk() (*[]BetaAppClipInvocationLocalization, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *BetaAppClipInvocationsResponse) SetIncluded(v []BetaAppClipInvocationLocalization)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *BetaAppClipInvocationsResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *BetaAppClipInvocationsResponse) GetLinks() PagedDocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *BetaAppClipInvocationsResponse) GetLinksOk() (*PagedDocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *BetaAppClipInvocationsResponse) SetLinks(v PagedDocumentLinks)`

SetLinks sets Links field to given value.


### GetMeta

`func (o *BetaAppClipInvocationsResponse) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *BetaAppClipInvocationsResponse) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *BetaAppClipInvocationsResponse) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *BetaAppClipInvocationsResponse) HasMeta() bool`

HasMeta returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


