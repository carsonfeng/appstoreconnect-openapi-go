# AppPricePointsV2Response

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**[]AppPricePointV2**](AppPricePointV2.md) |  | 
**Included** | Pointer to [**[]AppPricePointsV2ResponseIncludedInner**](AppPricePointsV2ResponseIncludedInner.md) |  | [optional] 
**Links** | [**PagedDocumentLinks**](PagedDocumentLinks.md) |  | 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 

## Methods

### NewAppPricePointsV2Response

`func NewAppPricePointsV2Response(data []AppPricePointV2, links PagedDocumentLinks, ) *AppPricePointsV2Response`

NewAppPricePointsV2Response instantiates a new AppPricePointsV2Response object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppPricePointsV2ResponseWithDefaults

`func NewAppPricePointsV2ResponseWithDefaults() *AppPricePointsV2Response`

NewAppPricePointsV2ResponseWithDefaults instantiates a new AppPricePointsV2Response object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *AppPricePointsV2Response) GetData() []AppPricePointV2`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *AppPricePointsV2Response) GetDataOk() (*[]AppPricePointV2, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *AppPricePointsV2Response) SetData(v []AppPricePointV2)`

SetData sets Data field to given value.


### GetIncluded

`func (o *AppPricePointsV2Response) GetIncluded() []AppPricePointsV2ResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *AppPricePointsV2Response) GetIncludedOk() (*[]AppPricePointsV2ResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *AppPricePointsV2Response) SetIncluded(v []AppPricePointsV2ResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *AppPricePointsV2Response) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *AppPricePointsV2Response) GetLinks() PagedDocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppPricePointsV2Response) GetLinksOk() (*PagedDocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppPricePointsV2Response) SetLinks(v PagedDocumentLinks)`

SetLinks sets Links field to given value.


### GetMeta

`func (o *AppPricePointsV2Response) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *AppPricePointsV2Response) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *AppPricePointsV2Response) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *AppPricePointsV2Response) HasMeta() bool`

HasMeta returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


