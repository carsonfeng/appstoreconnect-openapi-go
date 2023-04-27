# InAppPurchasePricesResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**[]InAppPurchasePrice**](InAppPurchasePrice.md) |  | 
**Included** | Pointer to [**[]InAppPurchasePricesResponseIncludedInner**](InAppPurchasePricesResponseIncludedInner.md) |  | [optional] 
**Links** | [**PagedDocumentLinks**](PagedDocumentLinks.md) |  | 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 

## Methods

### NewInAppPurchasePricesResponse

`func NewInAppPurchasePricesResponse(data []InAppPurchasePrice, links PagedDocumentLinks, ) *InAppPurchasePricesResponse`

NewInAppPurchasePricesResponse instantiates a new InAppPurchasePricesResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewInAppPurchasePricesResponseWithDefaults

`func NewInAppPurchasePricesResponseWithDefaults() *InAppPurchasePricesResponse`

NewInAppPurchasePricesResponseWithDefaults instantiates a new InAppPurchasePricesResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *InAppPurchasePricesResponse) GetData() []InAppPurchasePrice`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *InAppPurchasePricesResponse) GetDataOk() (*[]InAppPurchasePrice, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *InAppPurchasePricesResponse) SetData(v []InAppPurchasePrice)`

SetData sets Data field to given value.


### GetIncluded

`func (o *InAppPurchasePricesResponse) GetIncluded() []InAppPurchasePricesResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *InAppPurchasePricesResponse) GetIncludedOk() (*[]InAppPurchasePricesResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *InAppPurchasePricesResponse) SetIncluded(v []InAppPurchasePricesResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *InAppPurchasePricesResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *InAppPurchasePricesResponse) GetLinks() PagedDocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *InAppPurchasePricesResponse) GetLinksOk() (*PagedDocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *InAppPurchasePricesResponse) SetLinks(v PagedDocumentLinks)`

SetLinks sets Links field to given value.


### GetMeta

`func (o *InAppPurchasePricesResponse) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *InAppPurchasePricesResponse) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *InAppPurchasePricesResponse) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *InAppPurchasePricesResponse) HasMeta() bool`

HasMeta returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


