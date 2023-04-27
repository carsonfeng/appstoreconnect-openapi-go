# AppPricesV2Response

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**[]AppPriceV2**](AppPriceV2.md) |  | 
**Included** | Pointer to [**[]AppPricesV2ResponseIncludedInner**](AppPricesV2ResponseIncludedInner.md) |  | [optional] 
**Links** | [**PagedDocumentLinks**](PagedDocumentLinks.md) |  | 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 

## Methods

### NewAppPricesV2Response

`func NewAppPricesV2Response(data []AppPriceV2, links PagedDocumentLinks, ) *AppPricesV2Response`

NewAppPricesV2Response instantiates a new AppPricesV2Response object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppPricesV2ResponseWithDefaults

`func NewAppPricesV2ResponseWithDefaults() *AppPricesV2Response`

NewAppPricesV2ResponseWithDefaults instantiates a new AppPricesV2Response object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *AppPricesV2Response) GetData() []AppPriceV2`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *AppPricesV2Response) GetDataOk() (*[]AppPriceV2, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *AppPricesV2Response) SetData(v []AppPriceV2)`

SetData sets Data field to given value.


### GetIncluded

`func (o *AppPricesV2Response) GetIncluded() []AppPricesV2ResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *AppPricesV2Response) GetIncludedOk() (*[]AppPricesV2ResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *AppPricesV2Response) SetIncluded(v []AppPricesV2ResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *AppPricesV2Response) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *AppPricesV2Response) GetLinks() PagedDocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppPricesV2Response) GetLinksOk() (*PagedDocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppPricesV2Response) SetLinks(v PagedDocumentLinks)`

SetLinks sets Links field to given value.


### GetMeta

`func (o *AppPricesV2Response) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *AppPricesV2Response) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *AppPricesV2Response) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *AppPricesV2Response) HasMeta() bool`

HasMeta returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


