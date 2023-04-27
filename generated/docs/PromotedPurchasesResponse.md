# PromotedPurchasesResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**[]PromotedPurchase**](PromotedPurchase.md) |  | 
**Included** | Pointer to [**[]PromotedPurchasesResponseIncludedInner**](PromotedPurchasesResponseIncludedInner.md) |  | [optional] 
**Links** | [**PagedDocumentLinks**](PagedDocumentLinks.md) |  | 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 

## Methods

### NewPromotedPurchasesResponse

`func NewPromotedPurchasesResponse(data []PromotedPurchase, links PagedDocumentLinks, ) *PromotedPurchasesResponse`

NewPromotedPurchasesResponse instantiates a new PromotedPurchasesResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewPromotedPurchasesResponseWithDefaults

`func NewPromotedPurchasesResponseWithDefaults() *PromotedPurchasesResponse`

NewPromotedPurchasesResponseWithDefaults instantiates a new PromotedPurchasesResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *PromotedPurchasesResponse) GetData() []PromotedPurchase`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *PromotedPurchasesResponse) GetDataOk() (*[]PromotedPurchase, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *PromotedPurchasesResponse) SetData(v []PromotedPurchase)`

SetData sets Data field to given value.


### GetIncluded

`func (o *PromotedPurchasesResponse) GetIncluded() []PromotedPurchasesResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *PromotedPurchasesResponse) GetIncludedOk() (*[]PromotedPurchasesResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *PromotedPurchasesResponse) SetIncluded(v []PromotedPurchasesResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *PromotedPurchasesResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *PromotedPurchasesResponse) GetLinks() PagedDocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *PromotedPurchasesResponse) GetLinksOk() (*PagedDocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *PromotedPurchasesResponse) SetLinks(v PagedDocumentLinks)`

SetLinks sets Links field to given value.


### GetMeta

`func (o *PromotedPurchasesResponse) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *PromotedPurchasesResponse) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *PromotedPurchasesResponse) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *PromotedPurchasesResponse) HasMeta() bool`

HasMeta returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


