# AppPromotedPurchasesLinkagesResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**[]AppRelationshipsPromotedPurchasesDataInner**](AppRelationshipsPromotedPurchasesDataInner.md) |  | 
**Links** | [**PagedDocumentLinks**](PagedDocumentLinks.md) |  | 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 

## Methods

### NewAppPromotedPurchasesLinkagesResponse

`func NewAppPromotedPurchasesLinkagesResponse(data []AppRelationshipsPromotedPurchasesDataInner, links PagedDocumentLinks, ) *AppPromotedPurchasesLinkagesResponse`

NewAppPromotedPurchasesLinkagesResponse instantiates a new AppPromotedPurchasesLinkagesResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppPromotedPurchasesLinkagesResponseWithDefaults

`func NewAppPromotedPurchasesLinkagesResponseWithDefaults() *AppPromotedPurchasesLinkagesResponse`

NewAppPromotedPurchasesLinkagesResponseWithDefaults instantiates a new AppPromotedPurchasesLinkagesResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *AppPromotedPurchasesLinkagesResponse) GetData() []AppRelationshipsPromotedPurchasesDataInner`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *AppPromotedPurchasesLinkagesResponse) GetDataOk() (*[]AppRelationshipsPromotedPurchasesDataInner, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *AppPromotedPurchasesLinkagesResponse) SetData(v []AppRelationshipsPromotedPurchasesDataInner)`

SetData sets Data field to given value.


### GetLinks

`func (o *AppPromotedPurchasesLinkagesResponse) GetLinks() PagedDocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppPromotedPurchasesLinkagesResponse) GetLinksOk() (*PagedDocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppPromotedPurchasesLinkagesResponse) SetLinks(v PagedDocumentLinks)`

SetLinks sets Links field to given value.


### GetMeta

`func (o *AppPromotedPurchasesLinkagesResponse) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *AppPromotedPurchasesLinkagesResponse) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *AppPromotedPurchasesLinkagesResponse) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *AppPromotedPurchasesLinkagesResponse) HasMeta() bool`

HasMeta returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


