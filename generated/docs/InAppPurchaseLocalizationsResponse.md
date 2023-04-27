# InAppPurchaseLocalizationsResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**[]InAppPurchaseLocalization**](InAppPurchaseLocalization.md) |  | 
**Included** | Pointer to [**[]InAppPurchaseV2**](InAppPurchaseV2.md) |  | [optional] 
**Links** | [**PagedDocumentLinks**](PagedDocumentLinks.md) |  | 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 

## Methods

### NewInAppPurchaseLocalizationsResponse

`func NewInAppPurchaseLocalizationsResponse(data []InAppPurchaseLocalization, links PagedDocumentLinks, ) *InAppPurchaseLocalizationsResponse`

NewInAppPurchaseLocalizationsResponse instantiates a new InAppPurchaseLocalizationsResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewInAppPurchaseLocalizationsResponseWithDefaults

`func NewInAppPurchaseLocalizationsResponseWithDefaults() *InAppPurchaseLocalizationsResponse`

NewInAppPurchaseLocalizationsResponseWithDefaults instantiates a new InAppPurchaseLocalizationsResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *InAppPurchaseLocalizationsResponse) GetData() []InAppPurchaseLocalization`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *InAppPurchaseLocalizationsResponse) GetDataOk() (*[]InAppPurchaseLocalization, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *InAppPurchaseLocalizationsResponse) SetData(v []InAppPurchaseLocalization)`

SetData sets Data field to given value.


### GetIncluded

`func (o *InAppPurchaseLocalizationsResponse) GetIncluded() []InAppPurchaseV2`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *InAppPurchaseLocalizationsResponse) GetIncludedOk() (*[]InAppPurchaseV2, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *InAppPurchaseLocalizationsResponse) SetIncluded(v []InAppPurchaseV2)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *InAppPurchaseLocalizationsResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *InAppPurchaseLocalizationsResponse) GetLinks() PagedDocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *InAppPurchaseLocalizationsResponse) GetLinksOk() (*PagedDocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *InAppPurchaseLocalizationsResponse) SetLinks(v PagedDocumentLinks)`

SetLinks sets Links field to given value.


### GetMeta

`func (o *InAppPurchaseLocalizationsResponse) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *InAppPurchaseLocalizationsResponse) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *InAppPurchaseLocalizationsResponse) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *InAppPurchaseLocalizationsResponse) HasMeta() bool`

HasMeta returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


