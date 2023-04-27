# InAppPurchasePricePointsResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**[]InAppPurchasePricePoint**](InAppPurchasePricePoint.md) |  | 
**Included** | Pointer to [**[]Territory**](Territory.md) |  | [optional] 
**Links** | [**PagedDocumentLinks**](PagedDocumentLinks.md) |  | 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 

## Methods

### NewInAppPurchasePricePointsResponse

`func NewInAppPurchasePricePointsResponse(data []InAppPurchasePricePoint, links PagedDocumentLinks, ) *InAppPurchasePricePointsResponse`

NewInAppPurchasePricePointsResponse instantiates a new InAppPurchasePricePointsResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewInAppPurchasePricePointsResponseWithDefaults

`func NewInAppPurchasePricePointsResponseWithDefaults() *InAppPurchasePricePointsResponse`

NewInAppPurchasePricePointsResponseWithDefaults instantiates a new InAppPurchasePricePointsResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *InAppPurchasePricePointsResponse) GetData() []InAppPurchasePricePoint`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *InAppPurchasePricePointsResponse) GetDataOk() (*[]InAppPurchasePricePoint, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *InAppPurchasePricePointsResponse) SetData(v []InAppPurchasePricePoint)`

SetData sets Data field to given value.


### GetIncluded

`func (o *InAppPurchasePricePointsResponse) GetIncluded() []Territory`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *InAppPurchasePricePointsResponse) GetIncludedOk() (*[]Territory, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *InAppPurchasePricePointsResponse) SetIncluded(v []Territory)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *InAppPurchasePricePointsResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *InAppPurchasePricePointsResponse) GetLinks() PagedDocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *InAppPurchasePricePointsResponse) GetLinksOk() (*PagedDocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *InAppPurchasePricePointsResponse) SetLinks(v PagedDocumentLinks)`

SetLinks sets Links field to given value.


### GetMeta

`func (o *InAppPurchasePricePointsResponse) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *InAppPurchasePricePointsResponse) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *InAppPurchasePricePointsResponse) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *InAppPurchasePricePointsResponse) HasMeta() bool`

HasMeta returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


