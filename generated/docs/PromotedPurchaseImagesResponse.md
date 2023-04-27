# PromotedPurchaseImagesResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**[]PromotedPurchaseImage**](PromotedPurchaseImage.md) |  | 
**Included** | Pointer to [**[]PromotedPurchase**](PromotedPurchase.md) |  | [optional] 
**Links** | [**PagedDocumentLinks**](PagedDocumentLinks.md) |  | 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 

## Methods

### NewPromotedPurchaseImagesResponse

`func NewPromotedPurchaseImagesResponse(data []PromotedPurchaseImage, links PagedDocumentLinks, ) *PromotedPurchaseImagesResponse`

NewPromotedPurchaseImagesResponse instantiates a new PromotedPurchaseImagesResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewPromotedPurchaseImagesResponseWithDefaults

`func NewPromotedPurchaseImagesResponseWithDefaults() *PromotedPurchaseImagesResponse`

NewPromotedPurchaseImagesResponseWithDefaults instantiates a new PromotedPurchaseImagesResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *PromotedPurchaseImagesResponse) GetData() []PromotedPurchaseImage`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *PromotedPurchaseImagesResponse) GetDataOk() (*[]PromotedPurchaseImage, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *PromotedPurchaseImagesResponse) SetData(v []PromotedPurchaseImage)`

SetData sets Data field to given value.


### GetIncluded

`func (o *PromotedPurchaseImagesResponse) GetIncluded() []PromotedPurchase`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *PromotedPurchaseImagesResponse) GetIncludedOk() (*[]PromotedPurchase, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *PromotedPurchaseImagesResponse) SetIncluded(v []PromotedPurchase)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *PromotedPurchaseImagesResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *PromotedPurchaseImagesResponse) GetLinks() PagedDocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *PromotedPurchaseImagesResponse) GetLinksOk() (*PagedDocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *PromotedPurchaseImagesResponse) SetLinks(v PagedDocumentLinks)`

SetLinks sets Links field to given value.


### GetMeta

`func (o *PromotedPurchaseImagesResponse) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *PromotedPurchaseImagesResponse) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *PromotedPurchaseImagesResponse) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *PromotedPurchaseImagesResponse) HasMeta() bool`

HasMeta returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


