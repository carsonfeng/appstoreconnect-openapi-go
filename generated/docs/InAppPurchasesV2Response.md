# InAppPurchasesV2Response

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**[]InAppPurchaseV2**](InAppPurchaseV2.md) |  | 
**Included** | Pointer to [**[]InAppPurchasesV2ResponseIncludedInner**](InAppPurchasesV2ResponseIncludedInner.md) |  | [optional] 
**Links** | [**PagedDocumentLinks**](PagedDocumentLinks.md) |  | 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 

## Methods

### NewInAppPurchasesV2Response

`func NewInAppPurchasesV2Response(data []InAppPurchaseV2, links PagedDocumentLinks, ) *InAppPurchasesV2Response`

NewInAppPurchasesV2Response instantiates a new InAppPurchasesV2Response object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewInAppPurchasesV2ResponseWithDefaults

`func NewInAppPurchasesV2ResponseWithDefaults() *InAppPurchasesV2Response`

NewInAppPurchasesV2ResponseWithDefaults instantiates a new InAppPurchasesV2Response object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *InAppPurchasesV2Response) GetData() []InAppPurchaseV2`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *InAppPurchasesV2Response) GetDataOk() (*[]InAppPurchaseV2, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *InAppPurchasesV2Response) SetData(v []InAppPurchaseV2)`

SetData sets Data field to given value.


### GetIncluded

`func (o *InAppPurchasesV2Response) GetIncluded() []InAppPurchasesV2ResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *InAppPurchasesV2Response) GetIncludedOk() (*[]InAppPurchasesV2ResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *InAppPurchasesV2Response) SetIncluded(v []InAppPurchasesV2ResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *InAppPurchasesV2Response) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *InAppPurchasesV2Response) GetLinks() PagedDocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *InAppPurchasesV2Response) GetLinksOk() (*PagedDocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *InAppPurchasesV2Response) SetLinks(v PagedDocumentLinks)`

SetLinks sets Links field to given value.


### GetMeta

`func (o *InAppPurchasesV2Response) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *InAppPurchasesV2Response) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *InAppPurchasesV2Response) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *InAppPurchasesV2Response) HasMeta() bool`

HasMeta returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


