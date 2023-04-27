# AppPricePointsV3Response

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Data** | [**[]AppPricePointV3**](AppPricePointV3.md) |  | 
**Included** | Pointer to [**[]AppAvailabilityResponseIncludedInner**](AppAvailabilityResponseIncludedInner.md) |  | [optional] 
**Links** | [**PagedDocumentLinks**](PagedDocumentLinks.md) |  | 
**Meta** | Pointer to [**PagingInformation**](PagingInformation.md) |  | [optional] 

## Methods

### NewAppPricePointsV3Response

`func NewAppPricePointsV3Response(data []AppPricePointV3, links PagedDocumentLinks, ) *AppPricePointsV3Response`

NewAppPricePointsV3Response instantiates a new AppPricePointsV3Response object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewAppPricePointsV3ResponseWithDefaults

`func NewAppPricePointsV3ResponseWithDefaults() *AppPricePointsV3Response`

NewAppPricePointsV3ResponseWithDefaults instantiates a new AppPricePointsV3Response object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetData

`func (o *AppPricePointsV3Response) GetData() []AppPricePointV3`

GetData returns the Data field if non-nil, zero value otherwise.

### GetDataOk

`func (o *AppPricePointsV3Response) GetDataOk() (*[]AppPricePointV3, bool)`

GetDataOk returns a tuple with the Data field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetData

`func (o *AppPricePointsV3Response) SetData(v []AppPricePointV3)`

SetData sets Data field to given value.


### GetIncluded

`func (o *AppPricePointsV3Response) GetIncluded() []AppAvailabilityResponseIncludedInner`

GetIncluded returns the Included field if non-nil, zero value otherwise.

### GetIncludedOk

`func (o *AppPricePointsV3Response) GetIncludedOk() (*[]AppAvailabilityResponseIncludedInner, bool)`

GetIncludedOk returns a tuple with the Included field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIncluded

`func (o *AppPricePointsV3Response) SetIncluded(v []AppAvailabilityResponseIncludedInner)`

SetIncluded sets Included field to given value.

### HasIncluded

`func (o *AppPricePointsV3Response) HasIncluded() bool`

HasIncluded returns a boolean if a field has been set.

### GetLinks

`func (o *AppPricePointsV3Response) GetLinks() PagedDocumentLinks`

GetLinks returns the Links field if non-nil, zero value otherwise.

### GetLinksOk

`func (o *AppPricePointsV3Response) GetLinksOk() (*PagedDocumentLinks, bool)`

GetLinksOk returns a tuple with the Links field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLinks

`func (o *AppPricePointsV3Response) SetLinks(v PagedDocumentLinks)`

SetLinks sets Links field to given value.


### GetMeta

`func (o *AppPricePointsV3Response) GetMeta() PagingInformation`

GetMeta returns the Meta field if non-nil, zero value otherwise.

### GetMetaOk

`func (o *AppPricePointsV3Response) GetMetaOk() (*PagingInformation, bool)`

GetMetaOk returns a tuple with the Meta field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMeta

`func (o *AppPricePointsV3Response) SetMeta(v PagingInformation)`

SetMeta sets Meta field to given value.

### HasMeta

`func (o *AppPricePointsV3Response) HasMeta() bool`

HasMeta returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


