# CiProductsResponse

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**[]CiProduct**](CiProduct.md) |  | 
**Included** | Pointer to [**[]CiProductsResponseIncludedInner**](CiProductsResponseIncludedInner.md) |  | [optional] 
**Links** | [**PagedDocumentLinks**](PagedDocumentLinks.md) |  | 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 

## Methods

### NewCiProductsResponse

`func NewCiProductsResponse(data []CiProduct, links PagedDocumentLinks, ) *CiProductsResponse`

NewCiProductsResponse instantiates a new CiProductsResponse object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCiProductsResponseWithDefaults

`func NewCiProductsResponseWithDefaults() *CiProductsResponse`

NewCiProductsResponseWithDefaults instantiates a new CiProductsResponse object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *CiProductsResponse) GetData() []CiProduct`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *CiProductsResponse) GetDataOk() (*[]CiProduct, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *CiProductsResponse) SetData(v []CiProduct)`

SetData sets Data field to given value.


### GetIncluded

`func (o *CiProductsResponse) GetIncluded() []CiProductsResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *CiProductsResponse) GetIncludedOk() (*[]CiProductsResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *CiProductsResponse) SetIncluded(v []CiProductsResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *CiProductsResponse) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *CiProductsResponse) GetLinks() PagedDocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *CiProductsResponse) GetLinksOk() (*PagedDocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *CiProductsResponse) SetLinks(v PagedDocumentLinks)`

SetLinks sets Links field to given value.


### GetMeta

`func (o *CiProductsResponse) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *CiProductsResponse) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *CiProductsResponse) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *CiProductsResponse) HasMeta() bool`

HasMeta returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


